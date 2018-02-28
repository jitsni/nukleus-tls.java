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
package org.reaktivity.nukleus.tls.internal.stream;

import static java.nio.ByteBuffer.allocateDirect;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static javax.net.ssl.SSLEngineResult.Status.BUFFER_UNDERFLOW;
import static org.agrona.LangUtil.rethrowUnchecked;
import static org.reaktivity.nukleus.buffer.BufferPool.NO_SLOT;

import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.reaktivity.nukleus.buffer.BufferPool;
import org.reaktivity.nukleus.function.MessageConsumer;
import org.reaktivity.nukleus.function.MessagePredicate;
import org.reaktivity.nukleus.route.RouteManager;
import org.reaktivity.nukleus.stream.StreamFactory;
import org.reaktivity.nukleus.tls.internal.TlsConfiguration;
import org.reaktivity.nukleus.tls.internal.types.Flyweight;
import org.reaktivity.nukleus.tls.internal.types.OctetsFW;
import org.reaktivity.nukleus.tls.internal.types.control.RouteFW;
import org.reaktivity.nukleus.tls.internal.types.control.TlsRouteExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.AbortFW;
import org.reaktivity.nukleus.tls.internal.types.stream.BeginFW;
import org.reaktivity.nukleus.tls.internal.types.stream.DataFW;
import org.reaktivity.nukleus.tls.internal.types.stream.EndFW;
import org.reaktivity.nukleus.tls.internal.types.stream.ResetFW;
import org.reaktivity.nukleus.tls.internal.types.stream.TlsBeginExFW;
import org.reaktivity.nukleus.tls.internal.types.stream.WindowFW;
import org.reaktivity.nukleus.tls.internal.util.function.ObjectLongBiFunction;

public final class ClientStreamFactory implements StreamFactory
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private static final int MAXIMUM_HEADER_SIZE = 5 + 20 + 256;    // TODO version + MAC + padding
    private static final int MAXIMUM_PAYLOAD_LENGTH = (1 << Short.SIZE) - 1;

    private final RouteFW routeRO = new RouteFW();
    private final TlsRouteExFW tlsRouteExRO = new TlsRouteExFW();

    private final BeginFW beginRO = new BeginFW();
    private final DataFW dataRO = new DataFW();
    private final EndFW endRO = new EndFW();
    private final AbortFW abortRO = new AbortFW();

    private final BeginFW.Builder beginRW = new BeginFW.Builder();
    private final DataFW.Builder dataRW = new DataFW.Builder();
    private final EndFW.Builder endRW = new EndFW.Builder();
    private final AbortFW.Builder abortRW = new AbortFW.Builder();

    private final WindowFW windowRO = new WindowFW();
    private final ResetFW resetRO = new ResetFW();

    private final TlsBeginExFW tlsBeginExRO = new TlsBeginExFW();
    private final TlsBeginExFW.Builder tlsBeginExRW = new TlsBeginExFW.Builder();

    private final OctetsFW outNetOctetsRO = new OctetsFW();
    private final OctetsFW outAppOctetsRO = new OctetsFW();

    private final WindowFW.Builder windowRW = new WindowFW.Builder();
    private final ResetFW.Builder resetRW = new ResetFW.Builder();

    private final SSLContext context;
    private final RouteManager router;
    private final MutableDirectBuffer writeBuffer;
    private final BufferPool networkPool;
    private final BufferPool applicationPool;
    private final LongSupplier supplyStreamId;
    private final LongSupplier supplyCorrelationId;
    private final int handshakeWindowBytes;

    private final Long2ObjectHashMap<ClientHandshake> correlations;
    private final ByteBuffer inAppByteBuffer;
    private final ByteBuffer outAppByteBuffer;
    private final ByteBuffer outNetByteBuffer;
    private final DirectBuffer outNetBuffer;
    private long networkGroupId;

    private final Function<RouteFW, LongSupplier> supplyWriteFrameCounter;
    private final Function<RouteFW, LongSupplier> supplyReadFrameCounter;
    private final Function<RouteFW, LongConsumer> supplyWriteBytesAccumulator;
    private final Function<RouteFW, LongConsumer> supplyReadBytesAccumulator;

    public ClientStreamFactory(
        TlsConfiguration config,
        SSLContext context,
        RouteManager router,
        MutableDirectBuffer writeBuffer,
        BufferPool bufferPool,
        LongSupplier supplyStreamId,
        LongSupplier supplyCorrelationId,
        Long2ObjectHashMap<ClientHandshake> correlations,
        Function<RouteFW, LongSupplier> supplyReadFrameCounter,
        Function<RouteFW, LongConsumer> supplyReadBytesAccumulator,
        Function<RouteFW, LongSupplier> supplyWriteFrameCounter,
        Function<RouteFW, LongConsumer> supplyWriteBytesAccumulator)
    {
        this.context = requireNonNull(context);
        this.router = requireNonNull(router);
        this.writeBuffer = requireNonNull(writeBuffer);
        this.networkPool = requireNonNull(bufferPool);
        this.applicationPool = requireNonNull(bufferPool).duplicate();
        this.supplyStreamId = requireNonNull(supplyStreamId);
        this.supplyCorrelationId = requireNonNull(supplyCorrelationId);
        this.correlations = requireNonNull(correlations);
        this.handshakeWindowBytes = Math.min(config.handshakeWindowBytes(), networkPool.slotCapacity());

        this.inAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outAppByteBuffer = allocateDirect(writeBuffer.capacity());
        this.outNetByteBuffer = allocateDirect(Math.min(writeBuffer.capacity(), MAXIMUM_PAYLOAD_LENGTH));
        this.outNetBuffer = new UnsafeBuffer(outNetByteBuffer);

        this.supplyWriteFrameCounter = supplyWriteFrameCounter;
        this.supplyReadFrameCounter = supplyReadFrameCounter;
        this.supplyWriteBytesAccumulator = supplyWriteBytesAccumulator;
        this.supplyReadBytesAccumulator = supplyReadBytesAccumulator;
    }

    @Override
    public MessageConsumer newStream(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length,
        MessageConsumer throttle)
    {
        final BeginFW begin = beginRO.wrap(buffer, index, index + length);
        final long sourceRef = begin.sourceRef();

        MessageConsumer newStream = null;

        if (sourceRef == 0L)
        {
            newStream = newConnectReplyStream(begin, throttle);
        }
        else
        {
            newStream = newAcceptStream(begin, throttle);
        }

        return newStream;
    }

    private MessageConsumer newAcceptStream(
        final BeginFW begin,
        final MessageConsumer applicationThrottle)
    {
        final long applicationRef = begin.sourceRef();
        final String applicationName = begin.source().asString();
        final long authorization = begin.authorization();
        final OctetsFW extension = begin.extension();
        final TlsBeginExFW tlsBeginEx = extension.get(tlsBeginExRO::wrap);
        final boolean defaultRoute;

        final MessagePredicate defaultRouteFilter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    applicationProtocol == null;
        };

        final MessagePredicate filter = (t, b, o, l) ->
        {
            final RouteFW route = routeRO.wrap(b, o, l);
            final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
            final String hostname = routeEx.hostname().asString();
            final String applicationProtocol = routeEx.applicationProtocol().asString();
            final String tlsHostname = tlsBeginEx.hostname().asString();
            final String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();

            return applicationRef == route.sourceRef() &&
                    applicationName.equals(route.source().asString()) &&
                    (tlsHostname == null || Objects.equals(tlsHostname, hostname)) &&
                    (applicationProtocol == null || Objects.equals(tlsApplicationProtocol, applicationProtocol));
        };

        defaultRoute = router.resolve(authorization, defaultRouteFilter, this::wrapRoute) != null;
        final RouteFW route = router.resolve(authorization, filter, this::wrapRoute);

        MessageConsumer newStream = null;

        if (route != null)
        {
            String tlsHostname = tlsBeginEx.hostname().asString();
            if (tlsHostname == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                tlsHostname = routeEx.hostname().asString();
            }

            String tlsApplicationProtocol = tlsBeginEx.applicationProtocol().asString();
            if (tlsApplicationProtocol == null)
            {
                final TlsRouteExFW routeEx = route.extension().get(tlsRouteExRO::wrap);
                tlsApplicationProtocol = routeEx.applicationProtocol().asString();
            }

            final String networkName = route.target().asString();
            final long networkRef = route.targetRef();

            final long applicationId = begin.streamId();

            final LongSupplier writeFrameCounter = supplyWriteFrameCounter.apply(route);
            final LongSupplier readFrameCounter = supplyReadFrameCounter.apply(route);
            final LongConsumer writeBytesAccumulator = supplyWriteBytesAccumulator.apply(route);
            final LongConsumer readBytesAccumulator = supplyReadBytesAccumulator.apply(route);

            newStream = new ClientAcceptStream(
                tlsHostname,
                tlsApplicationProtocol,
                defaultRoute,
                applicationThrottle,
                applicationId,
                authorization,
                networkName,
                networkRef,
                writeFrameCounter,
                readFrameCounter,
                writeBytesAccumulator,
                readBytesAccumulator
                )::handleStream;
        }

        return newStream;
    }

    private MessageConsumer newConnectReplyStream(
        final BeginFW begin,
        final MessageConsumer networkReplyThrottle)
    {
        final long networkReplyId = begin.streamId();
        final long authorization =- begin.authorization();

        return new ClientConnectReplyStream(networkReplyThrottle, networkReplyId, authorization)::handleStream;
    }

    private RouteFW wrapRoute(
        int msgTypeId,
        DirectBuffer buffer,
        int index,
        int length)
    {
        return routeRO.wrap(buffer, index, index + length);
    }

    private final class ClientAcceptStream
    {
        private final String tlsHostname;
        private final String tlsApplicationProtocol;
        private final boolean defaultRoute;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;
        private final long authorization;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkRef;

        private final LongSupplier writeFrameCounter;
        private final LongSupplier readFrameCounter;
        private final LongConsumer writeBytesAccumulator;
        private final LongConsumer readBytesAccumulator;

        private SSLEngine tlsEngine;
        private MessageConsumer streamState;

        private long networkId;

        private int applicationBudget;
        private int applicationPadding;
        private int networkBudget;
        private int networkPadding;
        private long applicationGroupId;

        private ClientAcceptStream(
            String tlsHostname,
            String tlsApplicationProtocol,
            boolean defaultRoute,
            MessageConsumer applicationThrottle,
            long applicationId,
            long authorization,
            String networkName,
            long networkRef,
            LongSupplier writeFrameCounter,
            LongSupplier readFrameCounter,
            LongConsumer writeBytesAccumulator,
            LongConsumer readBytesAccumulator)
        {
            this.tlsHostname = tlsHostname;
            this.tlsApplicationProtocol = tlsApplicationProtocol;
            this.defaultRoute = defaultRoute;
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.authorization = authorization;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkRef = networkRef;
            this.writeFrameCounter = writeFrameCounter;
            this.readFrameCounter = readFrameCounter;
            this.writeBytesAccumulator = writeBytesAccumulator;
            this.readBytesAccumulator = readBytesAccumulator;
            this.streamState = this::beforeBegin;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                doReset(applicationThrottle, applicationId);
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                doReset(applicationThrottle, applicationId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            try
            {
                final String applicationName = begin.source().asString();
                final long applicationCorrelationId = begin.correlationId();
                final long authorization = begin.authorization();

                final long newNetworkId = supplyStreamId.getAsLong();
                final long newCorrelationId = supplyCorrelationId.getAsLong();

                final SSLEngine tlsEngine = context.createSSLEngine(tlsHostname, -1);
                tlsEngine.setUseClientMode(true);

                final SSLParameters tlsParameters = tlsEngine.getSSLParameters();
                tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
                if (tlsHostname != null)
                {
                    tlsParameters.setServerNames(asList(new SNIHostName(tlsHostname)));
                }

                if (tlsApplicationProtocol != null && !tlsApplicationProtocol.isEmpty())
                {
                    String[] applicationProtocols = new String[] { tlsApplicationProtocol };
                    tlsParameters.setApplicationProtocols(applicationProtocols);
                }

                tlsEngine.setSSLParameters(tlsParameters);

                final ClientHandshake newHandshake = new ClientHandshake(tlsEngine, tlsApplicationProtocol, defaultRoute,
                        networkName, newNetworkId,
                        authorization, applicationName, applicationCorrelationId, newCorrelationId, this::handleThrottle,
                        applicationThrottle, applicationId, this::handleNetworkReplyDone,
                        this::getNetworkBudget, this::getNetworkPadding,
                        this::setNetworkBudget, this::setNetworkPadding,
                        this::sendApplicationWindow,
                        writeFrameCounter,
                        readFrameCounter,
                        writeBytesAccumulator,
                        readBytesAccumulator);

                correlations.put(newCorrelationId, newHandshake);

                doBegin(networkTarget, newNetworkId, authorization, networkRef, newCorrelationId);
                router.setThrottle(networkName, newNetworkId, newHandshake::handleThrottle);

                this.tlsEngine = tlsEngine;
                this.networkId = newNetworkId;
                this.streamState = this::afterBegin;

                tlsEngine.beginHandshake();
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
                doAbort(networkTarget, networkId, authorization);
            }
        }

        private void handleData(
            DataFW data)
        {
            applicationBudget -= data.length() + data.padding();

            try
            {
                if (applicationBudget < 0)
                {
                    doReset(applicationThrottle, applicationId);
                    doCloseOutbound(tlsEngine, networkTarget, networkId, networkPadding,
                            authorization, this::handleNetworkReplyDone,
                            writeFrameCounter, writeBytesAccumulator);
                }
                else
                {
                    final OctetsFW payload = data.payload();

                    // Note: inAppBuffer is emptied by SslEngine.wrap(...)
                    //       so should be able to eliminate allocation+copy (stateless)
                    inAppByteBuffer.clear();
                    payload.buffer().getBytes(payload.offset(), inAppByteBuffer, payload.sizeof());
                    inAppByteBuffer.flip();

                    while (inAppByteBuffer.hasRemaining() && !tlsEngine.isOutboundDone())
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
                        if (result.bytesProduced() > 0)
                        {
                            networkBudget -= result.bytesProduced() + networkPadding;
                        }

                        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId, networkPadding,
                                authorization, this::handleNetworkReplyDone,
                                writeFrameCounter, writeBytesAccumulator);
                    }
                }
            }
            catch (SSLException ex)
            {
                doReset(applicationThrottle, applicationId);
                doAbort(networkTarget, networkId, authorization);
            }
        }

        private void handleEnd(
            EndFW end)
        {
            applicationBudget = -1;

            try
            {
                doCloseOutbound(tlsEngine, networkTarget, networkId, networkPadding,
                        authorization, this::handleNetworkReplyDone,
                        writeFrameCounter, writeBytesAccumulator);
            }
            catch (SSLException ex)
            {
                doAbort(networkTarget, networkId, authorization);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            tlsEngine.closeOutbound();
            doAbort(networkTarget, networkId, authorization);
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                handleWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void sendApplicationWindow()
        {
            final int applicationCredit = networkBudget - applicationBudget;

            if (applicationCredit > 0)
            {
                applicationBudget += applicationCredit;
                doWindow(applicationThrottle, applicationId, applicationCredit, applicationPadding, applicationGroupId);
            }
        }

        private void handleWindow(
            final WindowFW window)
        {
            networkBudget += window.credit();
            networkPadding = window.padding();
            networkGroupId = window.groupId();
            applicationPadding = networkPadding + MAXIMUM_HEADER_SIZE;
            sendApplicationWindow();
        }

        private void handleReset(
            ResetFW reset)
        {
            doReset(applicationThrottle, applicationId);
            tlsEngine.closeOutbound();
        }

        private void handleNetworkReplyDone()
        {
            if (applicationBudget == -1)
            {
                doReset(applicationThrottle, applicationId);
            }
        }

        int getNetworkBudget()
        {
            return networkBudget;
        }

        int getNetworkPadding()
        {
            return networkPadding;
        }

        void setNetworkBudget(int networkBudget)
        {
            this.networkBudget = networkBudget;
        }

        void setNetworkPadding(int networkPadding)
        {
            this.networkPadding = networkPadding;
        }
    }

    public final class ClientHandshake
    {
        private final SSLEngine tlsEngine;
        private final String applicationProtocol;
        private final boolean defaultRoute;

        private final String networkName;
        private final MessageConsumer networkTarget;
        private final long networkId;
        private final long networkAuthorization;
        private final MessageConsumer networkThrottle;

        private final MessageConsumer applicationThrottle;
        private final long applicationId;

        private final String applicationName;
        private final long applicationCorrelationId;
        private final long networkCorrelationId;

        private final Runnable networkReplyDoneHandler;

        private MessageConsumer networkReplyThrottle;
        private long networkReplyId;
        private int networkReplySlot = NO_SLOT;
        private int networkReplySlotOffset;

        private Consumer<WindowFW> windowHandler;
        private BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler;

        IntSupplier networkReplyBudgetSupplier;
        IntSupplier networkReplyPaddingSupplier;
        IntConsumer networkReplyBudgetConsumer;

        IntSupplier networkBudgetSupplier;
        IntSupplier networkPaddingSupplier;
        IntConsumer networkBudgetConsumer;
        IntConsumer networkPaddingConsumer;
        Runnable sendApplicationWindow;
        private int networkReplyGroupId;
        LongSupplier writeFrameCounter;
        LongSupplier readFrameCounter;
        LongConsumer writeBytesAccumulator;
        LongConsumer readBytesAccumulator;

        private ClientHandshake(
            SSLEngine tlsEngine,
            String applicationProtocol,
            boolean defaultRoute,
            String networkName,
            long networkId,
            long authorization,
            String applicationName,
            long applicationCorrelationId,
            long networkCorrelationId,
            MessageConsumer networkThrottle,
            MessageConsumer applicationThrottle,
            long applicationId,
            Runnable networkReplyDoneHandler,
            IntSupplier networkBudgetSupplier,
            IntSupplier networkPaddingSupplier,
            IntConsumer networkBudgetConsumer,
            IntConsumer networkPaddingConsumer,
            Runnable sendApplicationWindow,
            LongSupplier writeFrameCounter,
            LongSupplier readFrameCounter,
            LongConsumer writeBytesAccumulator,
            LongConsumer readBytesAccumulator)
        {
            this.tlsEngine = tlsEngine;
            this.applicationProtocol = applicationProtocol;
            this.defaultRoute = defaultRoute;
            this.networkName = networkName;
            this.networkTarget = router.supplyTarget(networkName);
            this.networkId = networkId;
            this.networkAuthorization = authorization;
            this.applicationName = applicationName;
            this.applicationCorrelationId = applicationCorrelationId;
            this.networkCorrelationId = networkCorrelationId;
            this.networkThrottle = networkThrottle;
            this.windowHandler = this::beforeNetworkReply;
            this.applicationThrottle = applicationThrottle;
            this.applicationId = applicationId;
            this.networkReplyDoneHandler = networkReplyDoneHandler;
            this.networkBudgetSupplier = networkBudgetSupplier;
            this.networkPaddingSupplier = networkPaddingSupplier;
            this.networkBudgetConsumer = networkBudgetConsumer;
            this.networkPaddingConsumer = networkPaddingConsumer;
            this.sendApplicationWindow = sendApplicationWindow;
            this.writeFrameCounter = writeFrameCounter;
            this.readFrameCounter = readFrameCounter;
            this.writeBytesAccumulator = writeBytesAccumulator;
            this.readBytesAccumulator = readBytesAccumulator;
        }

        @Override
        public String toString()
        {
            return String.format("%s [tlsEngine=%s]", getClass().getSimpleName(), tlsEngine);
        }

        private void onNetworkReply(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            BiConsumer<HandshakeStatus, Consumer<SSLEngineResult>> statusHandler,
            IntSupplier networkReplyBudgetSupplier,
            IntSupplier networkReplyPaddingSupplier,
            IntConsumer networkReplyBudgetConsumer)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.statusHandler = statusHandler;
            this.windowHandler = this::afterNetworkReply;
            this.networkReplyBudgetSupplier = networkReplyBudgetSupplier;
            this.networkReplyPaddingSupplier = networkReplyPaddingSupplier;
            this.networkReplyBudgetConsumer = networkReplyBudgetConsumer;

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private MessageConsumer doBeginApplicationReply(
            MessageConsumer applicationThrottle,
            long applicationReplyId)
        {
            final String applicationReplyName = applicationName;
            final String tlsPeerHost = tlsEngine.getPeerHost();

            String tlsApplicationProtocol0 = tlsEngine.getApplicationProtocol();
            if (tlsApplicationProtocol0 != null && tlsApplicationProtocol0.isEmpty())
            {
                tlsApplicationProtocol0 = null;
            }
            final String tlsApplicationProtocol = tlsApplicationProtocol0;

            final MessageConsumer applicationReply = router.supplyTarget(applicationReplyName);

            doTlsBegin(applicationReply, applicationReplyId, 0L, applicationCorrelationId,
                    tlsPeerHost, tlsApplicationProtocol);
            router.setThrottle(applicationReplyName, applicationReplyId, applicationThrottle);

            router.setThrottle(networkName, networkId, networkThrottle);

            sendApplicationWindow.run();

            return applicationReply;
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                windowHandler.accept(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void beforeNetworkReply(
            WindowFW window)
        {
            networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt()+window.credit());
            networkPaddingConsumer.accept(window.padding());
        }

        private void afterNetworkReply(
            WindowFW window)
        {
            networkBudgetConsumer.accept(networkBudgetSupplier.getAsInt()+window.credit());
            networkPaddingConsumer.accept(window.padding());

            statusHandler.accept(tlsEngine.getHandshakeStatus(), this::updateNetworkWindow);
        }

        private void handleReset(
            ResetFW reset)
        {
            try
            {
                if (correlations.remove(networkCorrelationId) == null)
                {
                    doReset(applicationThrottle, applicationId);
                }
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore
            }
        }

        private void afterBegin(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                doReset(networkReplyThrottle, networkReplyId);
                break;
            }
        }

        private void handleData(
            DataFW data)
        {
            int dataLength = data.length();

            readFrameCounter.getAsLong();
            readBytesAccumulator.accept(dataLength);

            networkReplyBudgetConsumer.accept(
                    networkReplyBudgetSupplier.getAsInt() - dataLength - data.padding());

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || networkReplyBudgetSupplier.getAsInt() < 0)
                {
                    doReset(networkReplyThrottle, networkReplyId);
                    doCloseOutbound(tlsEngine, networkTarget, networkId, networkPaddingSupplier.getAsInt(),
                            networkAuthorization, networkReplyDoneHandler,
                            writeFrameCounter, writeBytesAccumulator);
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset + payloadSize);

                    loop:
                    while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                    {
                        outAppByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        if (outAppByteBuffer.position() != 0)
                        {
                            doReset(networkReplyThrottle, networkReplyId);
                            break loop;
                        }

                        switch (result.getStatus())
                        {
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkReplySlotOffset = totalBytesRemaining;
                            break loop;
                        default:
                            networkReplySlotOffset = 0;
                            statusHandler.accept(result.getHandshakeStatus(), this::updateNetworkWindow);
                            break;
                        }
                    }

                    int networkReplyBudgetCredit = dataLength + networkReplyPaddingSupplier.getAsInt();
                    networkReplyBudgetConsumer.accept(
                            networkReplyBudgetSupplier.getAsInt() + networkReplyBudgetCredit);
                    doWindow(networkReplyThrottle, networkReplyId, networkReplyGroupId, networkReplyBudgetCredit,
                            networkReplyPaddingSupplier.getAsInt());
                }
            }
            catch (SSLException ex)
            {
                networkReplySlotOffset = 0;
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(networkTarget, networkId, networkAuthorization);
            }
            finally
            {
                if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
                {
                    networkPool.release(networkReplySlot);
                    networkReplySlot = NO_SLOT;
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            try
            {
                doCloseOutbound(tlsEngine, networkTarget, networkId, networkPaddingSupplier.getAsInt(),
                        networkAuthorization, networkReplyDoneHandler,
                        writeFrameCounter, writeBytesAccumulator);
            }
            catch (SSLException ex)
            {
                doAbort(networkTarget, networkId, networkAuthorization);
            }
            finally
            {
                doReset(networkThrottle, networkId);
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            correlations.remove(networkCorrelationId);
            tlsEngine.closeOutbound();
            doAbort(networkTarget, networkId, networkAuthorization);
        }

        private void updateNetworkWindow(
            SSLEngineResult result)
        {
            final int bytesProduced = result.bytesProduced();
            if (bytesProduced != 0)
            {
                final int networkBudget = networkBudgetSupplier.getAsInt();
                final int networkPadding = networkPaddingSupplier.getAsInt();
                networkBudgetConsumer.accept(networkBudget - bytesProduced - networkPadding);
            }
        }
    }

    private final class ClientConnectReplyStream
    {
        private final MessageConsumer networkReplyThrottle;
        private final long networkReplyId;

        private MessageConsumer networkTarget;
        private long networkId;
        private long networkAuthorization;

        private int networkReplyBudget;
        private int networkReplyPadding;
        private int applicationReplyBudget;
        private int applicationReplyPadding;

        private int networkReplySlot;
        private int networkReplySlotOffset;

        private SSLEngine tlsEngine;

        private MessageConsumer applicationReply;
        private long applicationReplyId;
        private final long applicationReplyAuthorization;
        private ObjectLongBiFunction<MessageConsumer, MessageConsumer> doBeginApplicationReply;

        private MessageConsumer streamState;
        private int applicationReplySlot = NO_SLOT;
        private int applicationReplySlotOffset;

        private Runnable networkReplyDoneHandler;
        private String applicationProtocol;
        private boolean defaultRoute;
        private IntSupplier networkPaddingSupplier;
        private long networkReplyGroupId;
        private long applicationReplyGroupId;

        private LongSupplier writeFrameCounter;
        private LongSupplier readFrameCounter;
        private LongConsumer writeBytesAccumulator;
        private LongConsumer readBytesAccumulator;

        private ClientConnectReplyStream(
            MessageConsumer networkReplyThrottle,
            long networkReplyId,
            long networkReplyAuthorization)
        {
            this.networkReplyThrottle = networkReplyThrottle;
            this.networkReplyId = networkReplyId;
            this.applicationReplyAuthorization = networkReplyAuthorization;
            this.streamState = this::beforeHandshake;
        }

        private void handleStream(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            streamState.accept(msgTypeId, buffer, index, length);
        }

        private void beforeHandshake(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            if (msgTypeId == BeginFW.TYPE_ID)
            {
                final BeginFW begin = beginRO.wrap(buffer, index, index + length);
                handleBegin(begin);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void afterHandshake(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case DataFW.TYPE_ID:
                final DataFW data = dataRO.wrap(buffer, index, index + length);
                handleData(data);
                break;
            case EndFW.TYPE_ID:
                final EndFW end = endRO.wrap(buffer, index, index + length);
                handleEnd(end);
                break;
            case AbortFW.TYPE_ID:
                final AbortFW abort = abortRO.wrap(buffer, index, index + length);
                handleAbort(abort);
                break;
            default:
                doReset(networkReplyThrottle, networkReplyId);
                break;
            }
        }

        private void handleBegin(
            BeginFW begin)
        {
            final long sourceRef = begin.sourceRef();
            final long correlationId = begin.correlationId();

            final ClientHandshake handshake = sourceRef == 0L ? correlations.remove(correlationId) : null;
            if (handshake != null)
            {
                this.tlsEngine = handshake.tlsEngine;
                this.applicationProtocol = handshake.applicationProtocol;
                this.defaultRoute = handshake.defaultRoute;
                this.networkTarget = handshake.networkTarget;
                this.networkId = handshake.networkId;
                this.networkPaddingSupplier = handshake.networkPaddingSupplier;
                this.networkAuthorization = handshake.networkAuthorization;
                this.networkReplySlot = handshake.networkReplySlot;
                this.networkReplySlotOffset = handshake.networkReplySlotOffset;
                this.doBeginApplicationReply = handshake::doBeginApplicationReply;
                this.streamState = handshake::afterBegin;
                this.networkReplyDoneHandler = handshake.networkReplyDoneHandler;
                this.writeFrameCounter = handshake.writeFrameCounter;
                this.readFrameCounter = handshake.readFrameCounter;
                this.writeBytesAccumulator = handshake.writeBytesAccumulator;
                this.readBytesAccumulator = handshake.readBytesAccumulator;

                networkReplyBudget += handshakeWindowBytes;
                doWindow(networkReplyThrottle, networkReplyId, networkReplyBudget, networkReplyPadding, networkReplyGroupId);

                handshake.onNetworkReply(networkReplyThrottle, networkReplyId, this::handleStatus,
                        this::getNetworkReplyBudget, this::getNetworkReplyPadding,
                        this::setNetworkReplyBudget);
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        int getNetworkReplyBudget()
        {
            return networkReplyBudget;
        }

        int getNetworkReplyPadding()
        {
            return networkReplyPadding;
        }

        void setNetworkReplyBudget(int networkReplyBudget)
        {
            this.networkReplyBudget = networkReplyBudget;
        }

        private void handleData(
            DataFW data)
        {
            final int dataLength = data.length();

            readFrameCounter.getAsLong();
            readBytesAccumulator.accept(dataLength);

            networkReplyBudget -= dataLength + data.padding();

            if (networkReplySlot == NO_SLOT)
            {
                networkReplySlot = networkPool.acquire(networkReplyId);
            }

            try
            {
                if (networkReplySlot == NO_SLOT || networkReplyBudget < 0)
                {
                    tlsEngine.closeInbound();
                    doReset(networkReplyThrottle, networkReplyId);
                    doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
                else
                {
                    final OctetsFW payload = data.payload();
                    final int payloadSize = payload.sizeof();

                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    inNetBuffer.putBytes(networkReplySlotOffset, payload.buffer(), payload.offset(), payloadSize);
                    networkReplySlotOffset += payloadSize;

                    unwrapNetworkBufferData();
                }
            }
            catch (SSLException ex)
            {
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
            }
            finally
            {
                if (networkReplySlotOffset == 0 && networkReplySlot != NO_SLOT)
                {
                    networkPool.release(networkReplySlot);
                    networkReplySlot = NO_SLOT;
                }
            }
        }

        private void unwrapNetworkBufferData()
        {
            assert (networkReplySlotOffset != 0);

            if (applicationReplySlot == NO_SLOT)
            {
                applicationReplySlot = applicationPool.acquire(applicationReplyId);
            }

            try
            {
                if (applicationReplySlot == NO_SLOT)
                {
                    tlsEngine.closeInbound();
                    doReset(networkReplyThrottle, networkReplyId);
                    doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
                else
                {
                    final MutableDirectBuffer inNetBuffer = networkPool.buffer(networkReplySlot);
                    final ByteBuffer inNetByteBuffer = networkPool.byteBuffer(networkReplySlot);
                    final int inNetByteBufferPosition = inNetByteBuffer.position();
                    inNetByteBuffer.limit(inNetByteBuffer.position() + networkReplySlotOffset);

                    loop:
                    while (inNetByteBuffer.hasRemaining() && !tlsEngine.isInboundDone())
                    {
                        final ByteBuffer outAppByteBuffer = applicationPool.byteBuffer(applicationReplySlot);
                        outAppByteBuffer.position(outAppByteBuffer.position() + applicationReplySlotOffset);

                        SSLEngineResult result = tlsEngine.unwrap(inNetByteBuffer, outAppByteBuffer);

                        switch (result.getStatus())
                        {
                        case BUFFER_OVERFLOW:
                        case BUFFER_UNDERFLOW:
                            final int totalBytesConsumed = inNetByteBuffer.position() - inNetByteBufferPosition;
                            final int totalBytesRemaining = inNetByteBuffer.remaining();
                            alignSlotBuffer(inNetBuffer, totalBytesConsumed, totalBytesRemaining);
                            networkReplySlotOffset = totalBytesRemaining;
                            if (networkReplySlotOffset == networkPool.slotCapacity() &&
                                    result.getStatus() == BUFFER_UNDERFLOW)
                            {
                                networkReplySlotOffset = 0;
                                tlsEngine.closeInbound();
                                doReset(networkReplyThrottle, networkReplyId);
                                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
                            }
                            else
                            {
                                final int networkWindowBytesUpdate =
                                    Math.max(networkPool.slotCapacity() - networkReplySlotOffset - networkReplyBudget, 0);

                                if (networkWindowBytesUpdate > 0)
                                {
                                    networkReplyBudget += networkWindowBytesUpdate;
                                    doWindow(networkReplyThrottle, networkReplyId, networkWindowBytesUpdate,
                                            networkReplyPadding, networkReplyGroupId);
                                }
                            }
                            break loop;
                        default:
                            networkReplySlotOffset = 0;
                            applicationReplySlotOffset += result.bytesProduced();
                            handleStatus(result.getHandshakeStatus(), r -> {});
                            break;
                        }
                    }

                    handleFlushAppData();
                }
            }
            catch (SSLException ex)
            {
                networkReplySlotOffset = 0;
                applicationReplySlotOffset = 0;
                doReset(networkReplyThrottle, networkReplyId);
                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
            }
            finally
            {
                if (applicationReplySlotOffset == 0 && applicationReplySlot != NO_SLOT)
                {
                    applicationPool.release(applicationReplySlot);
                    applicationReplySlot = NO_SLOT;
                }
            }
        }

        private void handleEnd(
            EndFW end)
        {
            if (!tlsEngine.isInboundDone())
            {
                networkReplyBudget = -1;
                try
                {
                    tlsEngine.closeInbound();
                    doEnd(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
                catch (SSLException ex)
                {
                    doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
                }
            }
        }

        private void handleAbort(
            AbortFW abort)
        {
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doAbort(applicationReply, applicationReplyId, applicationReplyAuthorization);
            }
        }

        private HandshakeStatus handleStatus(
            HandshakeStatus status,
            Consumer<SSLEngineResult> resultHandler)
        {
            loop:
            for (;;)
            {
                switch (status)
                {
                case NEED_TASK:
                    for (Runnable runnable = tlsEngine.getDelegatedTask();
                            runnable != null;
                            runnable = tlsEngine.getDelegatedTask())
                    {
                        runnable.run();
                    }

                    status = tlsEngine.getHandshakeStatus();
                    break;
                case NEED_WRAP:
                    try
                    {
                        outNetByteBuffer.rewind();
                        SSLEngineResult result = tlsEngine.wrap(EMPTY_BYTE_BUFFER, outNetByteBuffer);
                        resultHandler.accept(result);
                        flushNetwork(
                            tlsEngine,
                            result.bytesProduced(),
                            networkTarget,
                            networkId,
                            networkPaddingSupplier.getAsInt(),
                            networkAuthorization,
                            networkReplyDoneHandler,
                            writeFrameCounter,
                            writeBytesAccumulator);
                        status = result.getHandshakeStatus();
                    }
                    catch (SSLException ex)
                    {
                        // lambda interface cannot throw checked exception
                        rethrowUnchecked(ex);
                    }
                    break;
                case FINISHED:
                    handleFinished();
                    status = tlsEngine.getHandshakeStatus();
                    break;
                default:
                    break loop;
                }
            }

            return status;
        }

        private void handleFinished()
        {
            String tlsApplicationProtocol = tlsEngine.getApplicationProtocol();
            if ((tlsApplicationProtocol.equals("") && defaultRoute)
                    || Objects.equals(tlsApplicationProtocol, applicationProtocol))
            {
                // no ALPN negotiation && default route OR
                // negotiated protocol from ALPN matches with our route
                final long newApplicationReplyId = supplyStreamId.getAsLong();
                this.applicationReply = this.doBeginApplicationReply.apply(this::handleThrottle, newApplicationReplyId);
                this.applicationReplyId = newApplicationReplyId;

                this.streamState = this::afterHandshake;
                this.doBeginApplicationReply = null;
            }
            else
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }

        private void handleFlushAppData()
        {
            if (applicationReplySlotOffset > 0)
            {


                final MutableDirectBuffer outAppBuffer = applicationPool.buffer(applicationReplySlot);

                final int applicationWindow =
                        Math.min(applicationReplyBudget - applicationReplyPadding, MAXIMUM_PAYLOAD_LENGTH);

                final int applicationBytesConsumed = Math.min(applicationReplySlotOffset, applicationWindow);

                if (applicationBytesConsumed > 0)
                {
                    final OctetsFW outAppOctets = outAppOctetsRO.wrap(outAppBuffer, 0, applicationBytesConsumed);

                    doData(applicationReply, applicationReplyId, applicationReplyGroupId, applicationReplyPadding,
                            applicationReplyAuthorization, outAppOctets);

                    applicationReplyBudget -= applicationBytesConsumed + applicationReplyPadding;

                    applicationReplySlotOffset -= applicationBytesConsumed;

                    if (applicationReplySlotOffset != 0)
                    {
                        alignSlotBuffer(outAppBuffer, applicationBytesConsumed, applicationReplySlotOffset);
                    }
                }

            }

            if (applicationReplySlotOffset == 0 && tlsEngine.isInboundDone())
            {
                doEnd(applicationReply, applicationReplyId, applicationReplyAuthorization);
                if (networkReplyBudget == -1)
                {
                    doReset(networkReplyThrottle, networkReplyId);
                }
            }
        }

        private void handleThrottle(
            int msgTypeId,
            DirectBuffer buffer,
            int index,
            int length)
        {
            switch (msgTypeId)
            {
            case WindowFW.TYPE_ID:
                final WindowFW window = windowRO.wrap(buffer, index, index + length);
                handleWindow(window);
                break;
            case ResetFW.TYPE_ID:
                final ResetFW reset = resetRO.wrap(buffer, index, index + length);
                handleReset(reset);
                break;
            default:
                // ignore
                break;
            }
        }

        private void handleWindow(
            WindowFW window)
        {
            applicationReplyBudget += window.credit();
            applicationReplyPadding = networkReplyPadding = window.padding();
            applicationReplyGroupId = networkReplyGroupId = window.groupId();
System.out.printf("TLSC recv WINDOW(%d) applicationReplyGroupId=%d networkReplyGroupId=%d\n", window.credit(),
        applicationReplyGroupId, networkReplyGroupId);

            if (applicationReplySlotOffset != 0)
            {
                try
                {
                    handleFlushAppData();
                }
                finally
                {
                    if (applicationReplySlotOffset == 0)
                    {
                        applicationPool.release(applicationReplySlot);
                        applicationReplySlot = NO_SLOT;
                    }
                }
            }

            if (networkReplySlotOffset != 0)
            {
                try
                {
                    unwrapNetworkBufferData();
                }
                finally
                {
                    if (networkReplySlotOffset == 0)
                    {
                        networkPool.release(networkReplySlot);
                        networkReplySlot = NO_SLOT;
                    }
                }
            }

            final int networkCredit = applicationReplyBudget - networkReplyBudget - networkReplySlotOffset;

            if (networkCredit > 0)
            {
                networkReplyBudget += networkCredit;
                doWindow(networkReplyThrottle, networkReplyId, networkCredit, networkReplyPadding, networkReplyGroupId);
        System.out.printf("TLSC send WINDOW(%d) applicationReplyGroupId=%d networkReplyGroupId=%d\n", networkCredit,
                applicationReplyGroupId, networkReplyGroupId);
            }
        }

        private void handleReset(
            ResetFW reset)
        {
            try
            {
                tlsEngine.closeInbound();
            }
            catch (SSLException ex)
            {
                // ignore and clean up
            }
            finally
            {
                doReset(networkReplyThrottle, networkReplyId);
            }
        }
    }

    private void flushNetwork(
        SSLEngine tlsEngine,
        int bytesProduced,
        MessageConsumer networkTarget,
        long networkId,
        int padding,
        long authorization,
        Runnable networkReplyDoneHandler,
        LongSupplier writeFrameCounter,
        LongConsumer writeBytesAccumulator)
    {
        if (bytesProduced > 0)
        {
            final OctetsFW outNetOctets = outNetOctetsRO.wrap(outNetBuffer, 0, bytesProduced);
            doData(networkTarget, networkId, networkGroupId, padding, authorization, outNetOctets);
            writeFrameCounter.getAsLong();
            writeBytesAccumulator.accept(bytesProduced);
        }

        if (tlsEngine.isOutboundDone())
        {
            doEnd(networkTarget, networkId, authorization);
            networkReplyDoneHandler.run();
        }
    }

    private void alignSlotBuffer(
        final MutableDirectBuffer slotBuffer,
        final int bytesConsumed,
        final int bytesRemaining)
    {
        if (bytesConsumed > 0)
        {
            writeBuffer.putBytes(0, slotBuffer, bytesConsumed, bytesRemaining);
            slotBuffer.putBytes(0, writeBuffer, 0, bytesRemaining);
        }
    }

    private void doTlsBegin(
        MessageConsumer target,
        long targetId,
        long targetRef,
        long correlationId,
        String hostname,
        String applicationProtocol)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                                     .streamId(targetId)
                                     .source("tls")
                                     .sourceRef(targetRef)
                                     .correlationId(correlationId)
                                     .extension(e -> e.set(visitTlsBeginEx(hostname, applicationProtocol)))
                                     .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private Flyweight.Builder.Visitor visitTlsBeginEx(
        String hostname,
        String applicationProtocol)
    {
        return (buffer, offset, limit) ->
            tlsBeginExRW.wrap(buffer, offset, limit)
                        .hostname(hostname)
                        .applicationProtocol(applicationProtocol)
                        .build()
                        .sizeof();
    }

    private void doBegin(
        final MessageConsumer target,
        final long targetId,
        final long authorization,
        final long targetRef,
        final long correlationId)
    {
        final BeginFW begin = beginRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .source("tls")
                .sourceRef(targetRef)
                .correlationId(correlationId)
                .build();

        target.accept(begin.typeId(), begin.buffer(), begin.offset(), begin.sizeof());
    }

    private void doData(
        final MessageConsumer target,
        final long targetId,
        final long groupId,
        final int padding,
        final long authorization,
        final OctetsFW payload)
    {
        final DataFW data = dataRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .groupId(groupId)
                .padding(padding)
                .payload(p -> p.set(payload.buffer(), payload.offset(), payload.sizeof()))
                .build();

        target.accept(data.typeId(), data.buffer(), data.offset(), data.sizeof());
    }

    private void doEnd(
        final MessageConsumer target,
        final long targetId,
        final long authorization)
    {
        final EndFW end = endRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .build();

        target.accept(end.typeId(), end.buffer(), end.offset(), end.sizeof());
    }

    private void doAbort(
        final MessageConsumer target,
        final long targetId,
        final long authorization)
    {
        final AbortFW abort = abortRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(targetId)
                .authorization(authorization)
                .build();

        target.accept(abort.typeId(), abort.buffer(), abort.offset(), abort.sizeof());
    }

    private void doWindow(
        final MessageConsumer throttle,
        final long throttleId,
        final int credit,
        final int padding,
        final long groupId)
    {
        final WindowFW window = windowRW.wrap(writeBuffer, 0, writeBuffer.capacity())
                .streamId(throttleId)
                .credit(credit)
                .padding(padding)
                .groupId(groupId)
                .build();

        throttle.accept(window.typeId(), window.buffer(), window.offset(), window.sizeof());
    }

    private void doReset(
        final MessageConsumer throttle,
        final long throttleId)
    {
        final ResetFW reset = resetRW.wrap(writeBuffer, 0, writeBuffer.capacity())
               .streamId(throttleId)
               .build();

        throttle.accept(reset.typeId(), reset.buffer(), reset.offset(), reset.sizeof());
    }

    private void doCloseOutbound(
        SSLEngine tlsEngine,
        MessageConsumer networkTarget,
        long networkId,
        int networkPadding,
        long authorization,
        Runnable networkReplyDoneHandler,
        LongSupplier writeFrameCounter,
        LongConsumer writeBytesAccumulator) throws SSLException
    {
        tlsEngine.closeOutbound();
        outNetByteBuffer.rewind();
        SSLEngineResult result = tlsEngine.wrap(inAppByteBuffer, outNetByteBuffer);
        if (result.bytesProduced() > 0)
        {
            // networkWindowBudget -= result.bytesProduced() + networkWindowPadding;
        }
        flushNetwork(tlsEngine, result.bytesProduced(), networkTarget, networkId, networkPadding, authorization,
                networkReplyDoneHandler, writeFrameCounter, writeBytesAccumulator);
    }

}
