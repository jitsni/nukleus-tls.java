/**
 * Copyright 2016-2019 The Reaktivity Project
 *
 * The Reaktivity Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package org.reaktivity.nukleus.tls.internal;

import static java.lang.System.getProperty;
import static org.reaktivity.nukleus.route.RouteKind.CLIENT;
import static org.reaktivity.nukleus.route.RouteKind.SERVER;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.DirectBuffer;
import org.agrona.LangUtil;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.internal.CopyOnWriteHashMap;
import org.reaktivity.nukleus.route.RouteKind;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.control.UnrouteFW;

final class TlsNukleus implements Nukleus
{
    static final String NAME = "tls";

    private static final String PROPERTY_TLS_KEYSTORE = "tls.keystore";
    private static final String PROPERTY_TLS_KEYSTORE_TYPE = "tls.keystore.type";
    private static final String PROPERTY_TLS_KEYSTORE_PASSWORD = "tls.keystore.password";
    private static final String PROPERTY_TLS_TRUSTSTORE = "tls.truststore";
    private static final String PROPERTY_TLS_TRUSTSTORE_TYPE = "tls.truststore.type";
    private static final String PROPERTY_TLS_TRUSTSTORE_PASSWORD = "tls.truststore.password";

    private static final String DEFAULT_TLS_KEYSTORE = "keys";
    private static final String DEFAULT_TLS_KEYSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_KEYSTORE_PASSWORD = "generated";
    private static final String DEFAULT_TLS_TRUSTSTORE = "trust";
    private static final String DEFAULT_TLS_TRUSTSTORE_TYPE = "JKS";
    private static final String DEFAULT_TLS_TRUSTSTORE_PASSWORD = "generated";

    private final UnrouteFW unrouteRO = new UnrouteFW();
    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final TlsConfiguration config;
    private final Map<RouteKind, MessagePredicate> routeHandlers;
    private final Map<Long, String> storesByRouteId;

    private final Map<String, StoreInfo> contextsByStore;

    private int storeIndex;

    TlsNukleus(
        TlsConfiguration config)
    {
        this.config = config;

        this.storesByRouteId = new HashMap<>();
        this.contextsByStore = new CopyOnWriteHashMap<>();

        Map<RouteKind, MessagePredicate> routeHandlers = new EnumMap<>(RouteKind.class);
        routeHandlers.put(SERVER, this::handleRoute);
        routeHandlers.put(CLIENT, this::handleRoute);
        this.routeHandlers = routeHandlers;
    }

    @Override
    public String name()
    {
        return TlsNukleus.NAME;
    }

    @Override
    public TlsConfiguration config()
    {
        return config;
    }

    @Override
    public MessagePredicate routeHandler(
        RouteKind kind)
    {
        return routeHandlers.get(kind);
    }

    @Override
    public TlsElektron supplyElektron()
    {
        return new TlsElektron(config, contextsByStore::get);
    }

    private boolean handleRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        boolean handled = false;
        switch(msgTypeId)
        {
            case RouteFW.TYPE_ID:
            {
                final RouteFW route = routeRO.wrap(buffer, index, index + length);
                handled = handleRoute(route);
            }
            break;
            case UnrouteFW.TYPE_ID:
            {
                final UnrouteFW unroute = unrouteRO.wrap(buffer, index, index + length);
                handled = handleUnroute(unroute);
            }
            break;
        }
        return handled;
    }

    private boolean handleRoute(
        final RouteFW route)
    {
        final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
        final String store = routeEx.store().asString();
        final long routeId = route.correlationId();

        storesByRouteId.put(routeId, store);
        StoreInfo storeInfo = contextsByStore.computeIfAbsent(store, this::newStoreInfo);
        if (storeInfo != null)
        {
            storeInfo.routeCount++;
        }

        return storeInfo != null;
    }

    private boolean handleUnroute(
        final UnrouteFW unroute)
    {
        final long routeId = unroute.routeId();
        final String store = storesByRouteId.remove(routeId);
        StoreInfo storeInfo = contextsByStore.get(store);
        storeInfo.routeCount--;
        if (storeInfo.routeCount == 0)
        {
            contextsByStore.remove(store);
        }
        return true;
    }

    private StoreInfo newStoreInfo(
        String store)
    {
        Path directory = config.directory();
        SSLContext context = null;
        Set<String> caDnames = new LinkedHashSet<>();
        boolean trustStoreExists = false;

        try
        {
            String keyStorePassword = getProperty(PROPERTY_TLS_KEYSTORE_PASSWORD, DEFAULT_TLS_KEYSTORE_PASSWORD);
            String keyStoreFilename = getProperty(PROPERTY_TLS_KEYSTORE, DEFAULT_TLS_KEYSTORE);
            String keyStoreType = getProperty(PROPERTY_TLS_KEYSTORE_TYPE, DEFAULT_TLS_KEYSTORE_TYPE);
            File keyStoreFile = resolve(directory, store, keyStoreFilename);

            KeyManager[] keyManagers = null;
            if (keyStoreFile.exists())
            {
                KeyStore keyStore = KeyStore.getInstance(keyStoreType);
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        config.keyManagerAlgorithm());
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            String trustStorePassword = getProperty(PROPERTY_TLS_TRUSTSTORE_PASSWORD, DEFAULT_TLS_TRUSTSTORE_PASSWORD);
            String trustStoreFilename = System.getProperty(PROPERTY_TLS_TRUSTSTORE, DEFAULT_TLS_TRUSTSTORE);
            String trustStoreType = System.getProperty(PROPERTY_TLS_TRUSTSTORE_TYPE, DEFAULT_TLS_TRUSTSTORE_TYPE);
            File trustStoreFile = resolve(directory, store, trustStoreFilename);

            TrustManager[] trustManagers = null;
            if (trustStoreFile.exists())
            {
                trustStoreExists = true;
                KeyStore trustStore = KeyStore.getInstance(trustStoreType);
                trustStore.load(new FileInputStream(trustStoreFile), trustStorePassword.toCharArray());
                // TODO: TLS Alert Record, code 112 / scope trustStore to match routes?
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                        TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();

                if (++storeIndex > 255)
                {
                    // cannot fit in 1 byte
                    return null;
                }

                for(String alias : Collections.list(trustStore.aliases()))
                {
                    if (trustStore.isCertificateEntry(alias))
                    {
                        Certificate certificate = trustStore.getCertificate(alias);
                        String dn = ((X509Certificate) certificate).getSubjectX500Principal().getName();
                        caDnames.add(dn);
                    }
                }
            }

            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, new SecureRandom());
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return new StoreInfo(store, storeIndex, context, trustStoreExists, caDnames);
    }

    private static File resolve(
        Path directory,
        String store,
        String storeFilename)
    {
        return store == null
                ? directory.resolve("tls").resolve(storeFilename).toFile()
                : directory.resolve("tls").resolve("stores").resolve(store).resolve(storeFilename).toFile();
    }
}
