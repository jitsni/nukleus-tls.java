/**
 * Copyright 2016-2017 The Reaktivity Project
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.agrona.LangUtil;
import org.reaktivity.nukleus.Configuration;
import org.reaktivity.nukleus.Nukleus;
import org.reaktivity.nukleus.NukleusBuilder;
import org.reaktivity.nukleus.NukleusFactorySpi;
import org.reaktivity.nukleus.tls.internal.stream.ClientStreamFactoryBuilder;
import org.reaktivity.nukleus.tls.internal.stream.ServerStreamFactoryBuilder;

public final class TlsNukleusFactorySpi implements NukleusFactorySpi
{
    private static final String PROPERTY_TLS_KEYSTORE = "tls.keystore";
    private static final String PROPERTY_TLS_KEYSTORE_PASSWORD = "tls.keystore.password";
    private static final String PROPERTY_TLS_TRUSTSTORE = "tls.truststore";
    private static final String PROPERTY_TLS_TRUSTSTORE_PASSWORD = "tls.truststore.password";

    private static final String DEFAULT_TLS_KEYSTORE = "keys";
    private static final String DEFAULT_TLS_KEYSTORE_PASSWORD = "generated";
    private static final String DEFAULT_TLS_TRUSTSTORE = "trust";
    private static final String DEFAULT_TLS_TRUSTSTORE_PASSWORD = "generated";

    @Override
    public String name()
    {
        return "tls";
    }

    @Override
    public Nukleus create(
        Configuration config,
        NukleusBuilder builder)
    {
        final TlsConfiguration tlsConfig = new TlsConfiguration(config);
        final Path directory = config.directory();
        final SSLContext context = initContext(directory);

        final ServerStreamFactoryBuilder serverStreamFactoryBuilder =
            new ServerStreamFactoryBuilder(
                tlsConfig,
                context);

        final ClientStreamFactoryBuilder clientStreamFactoryBuilder =
            new ClientStreamFactoryBuilder(
                tlsConfig,
                context);

        return builder.streamFactory(SERVER, serverStreamFactoryBuilder)
                      .routeHandler(SERVER, serverStreamFactoryBuilder::handleRoute)
                      .streamFactory(CLIENT, clientStreamFactoryBuilder)
                      .routeHandler(CLIENT, clientStreamFactoryBuilder::handleRoute)
                      .build();
    }

    private SSLContext initContext(
        Path directory)
    {
        SSLContext context = null;

        try
        {
            String keyStorePassword = getProperty(PROPERTY_TLS_KEYSTORE_PASSWORD, DEFAULT_TLS_KEYSTORE_PASSWORD);
            String keyStoreFilename = getProperty(PROPERTY_TLS_KEYSTORE, DEFAULT_TLS_KEYSTORE);
            File keyStoreFile = directory.resolve("tls").resolve(keyStoreFilename).toFile();

            KeyManager[] keyManagers = null;
            if (keyStoreFile.exists())
            {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword.toCharArray());
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }

            String trustStorePassword = getProperty(PROPERTY_TLS_TRUSTSTORE_PASSWORD, DEFAULT_TLS_TRUSTSTORE_PASSWORD);
            String trustStoreFilename = System.getProperty(PROPERTY_TLS_TRUSTSTORE, DEFAULT_TLS_TRUSTSTORE);
            File trustStoreFile = directory.resolve("tls").resolve(trustStoreFilename).toFile();

            TrustManager[] trustManagers = null;
            if (trustStoreFile.exists())
            {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream(trustStoreFile), trustStorePassword.toCharArray());
                // TODO: TLS Alert Record, code 112 / scope trustStore to match routes?
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
                trustManagerFactory.init(trustStore);
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, new SecureRandom());
        }
        catch (Exception ex)
        {
            LangUtil.rethrowUnchecked(ex);
        }

        return context;
    }
}
