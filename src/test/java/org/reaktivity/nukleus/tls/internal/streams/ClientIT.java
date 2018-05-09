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
package org.reaktivity.nukleus.tls.internal.streams;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.reaktor.test.ReaktorRule;

public class ClientIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/tls/control/route")
            .addScriptRoot("client", "org/reaktivity/specification/nukleus/tls/streams")
            .addScriptRoot("server", "org/reaktivity/specification/tls");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(1024)
            .nukleus("tls"::equals)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEstablishConnection() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/client.auth/client",
            "${server}/client.auth/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEstablishConnectionWithClientAuth() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client.alpn/controller",
            "${client}/connection.established.with.alpn/client",
            "${server}/connection.established.with.alpn/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEstablishConnectionWithAlpn() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/connection.established.no.hostname.no.alpn/client",
            "${server}/connection.established.no.hostname.no.alpn/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEstablishConnectionWithNoHostnameNoAlpn() throws Exception
    {
        k3po.finish();
    }

    /*
     * No route for protocol2, route for null protocol
     * > BEGIN=protocol2
     * negotiates successfully without ALPN, so protocol == "" => null
     * need to reverify route still matches with negotiated protocol
     * < BEGIN=null
     */
    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/connection.established.with.alpn/client",
            "${server}/connection.established/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldNegotiateWithNoALPNAsNoProtocolRouteExists() throws Exception
    {
        k3po.finish();
    }

    /*
     * only one route, for protocol2
     * > BEGIN=protocol2
     * negotiates successfully without ALPN, so protocol == "" => null
     * need to reverify route still matches with negotiated protocol
     * < RESET
     */
    @Ignore("https://github.com/k3po/k3po/issues/454 - Support connect aborted")
    @Test
    @Specification({
            "${route}/client.alpn/controller",
            "${client}/connection.established.with.alpn/client",
            "${server}/connection.established/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldFailNoALPNNoDefaultRoute() throws Exception
    {
        k3po.finish();
    }

    /*
     * two routes, one for protocol2, one for null, both to same target + targetRef
     * > BEGIN=protocol2
     * negotiates successfully without ALPN, so protocol == "" => null
     * need to reverify route target + targetRef still matches with negotiated protocol
     * < BEGIN=null
     */
    @Test
    @Specification({
            "${route}/client.alpn.default/controller",
            "${client}/connection.established.with.alpn/client",
            "${server}/connection.established/server" })
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldSucceedNoALPNDefaultRoute() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"",
        "authorization 0x0001_000000000000L"})
    public void shouldEstablishConnectionWithAuthorization() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.10k/client",
        "${server}/echo.payload.length.10k/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength10k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.10k/client",
        "${server}/echo.payload.length.10k/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength10kWithAuthorization() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.100k/client",
        "${server}/echo.payload.length.100k/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength100k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/echo.payload.length.1000k/client",
        "${server}/echo.payload.length.1000k/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength1000k() throws Exception
    {
        k3po.finish();
    }

    @Ignore("handshake doesn't succeed due to write close race")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.close/client",
        "${server}/server.sent.write.close/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Ignore("handshake doesn't succeed due to write close race")
    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/server.sent.write.close.before.correlated/client",
            "${server}/server.sent.write.close.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteCloseBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.close/client",
        "${server}/client.sent.write.close/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/client.sent.write.close.before.correlated/client",
            "${server}/client.sent.write.close.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteCloseBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.write.abort/client",
        "${server}/server.sent.write.abort/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/server.sent.write.abort.before.correlated/client",
            "${server}/server.sent.write.abort.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteAbortBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.write.abort/client",
        "${server}/client.sent.write.abort/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/client.sent.write.abort.before.correlated/client",
            "${server}/client.sent.write.abort.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteAbortBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }

    @Ignore("DATA vs RESET read order not yet guaranteed to match write order")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/server.sent.read.abort/client",
        "${server}/server.sent.read.abort/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Ignore("DATA vs RESET read order not yet guaranteed to match write order")
    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/server.sent.read.abort.before.correlated/client",
            "${server}/server.sent.read.abort.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentReadAbortBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }

    @Ignore("DATA vs RESET read order not yet guaranteed to match write order")
    @Test
    @Specification({
        "${route}/client/controller",
        "${client}/client.sent.read.abort/client",
        "${server}/client.sent.read.abort/server"})
    @ScriptProperty({
        "newServerAcceptRef ${newClientConnectRef}",
        "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Ignore("DATA vs RESET read order not yet guaranteed to match write order")
    @Test
    @Specification({
            "${route}/client/controller",
            "${client}/client.sent.read.abort.before.correlated/client",
            "${server}/client.sent.read.abort.before.correlated/server"})
    @ScriptProperty({
            "newServerAcceptRef ${newClientConnectRef}",
            "serverAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentReadAbortBeforeCorrelated() throws Exception
    {
        k3po.finish();
    }
}
