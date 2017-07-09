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
import static org.reaktivity.reaktor.internal.ReaktorConfiguration.ABORT_STREAM_FRAME_TYPE_ID;

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.nukleus.tls.internal.types.stream.AbortFW;
import org.reaktivity.reaktor.test.ReaktorRule;

public class ServerIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/tls/control/route")
            .addScriptRoot("client", "org/reaktivity/specification/tls")
            .addScriptRoot("server", "org/reaktivity/specification/nukleus/tls/streams");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(1024)
            .nukleus("tls"::equals)
            .configure(ABORT_STREAM_FRAME_TYPE_ID, AbortFW.TYPE_ID)
            .clean();

    @Rule
    public final TestRule chain = outerRule(reaktor).around(k3po).around(timeout);

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/connection.established/client",
        "${server}/connection.established/server" })
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEstablishConnection() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/echo.payload.length.10k/client",
        "${server}/echo.payload.length.10k/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength10k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/echo.payload.length.100k/client",
        "${server}/echo.payload.length.100k/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength100k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/echo.payload.length.1000k/client",
        "${server}/echo.payload.length.1000k/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldEchoPayloadLength1000k() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/server.sent.write.close/client",
        "${server}/server.sent.write.close/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/client.sent.write.close/client",
        "${server}/client.sent.write.close/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteClose() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/server.sent.write.abort/client",
        "${server}/server.sent.write.abort/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/client.sent.write.abort/client",
        "${server}/client.sent.write.abort/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentWriteAbort() throws Exception
    {
        k3po.finish();
    }

    @Ignore("BEGIN vs RESET read order not yet guaranteed to match write order")
    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/server.sent.read.abort/client",
        "${server}/server.sent.read.abort/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveServerSentReadAbort() throws Exception
    {
        k3po.finish();
    }

    @Test
    @Specification({
        "${route}/server/controller",
        "${client}/client.sent.read.abort/client",
        "${server}/client.sent.read.abort/server"})
    @ScriptProperty({
        "newClientAcceptRef ${newServerConnectRef}",
        "clientAccept \"nukleus://target/streams/tls#source\"" })
    public void shouldReceiveClientSentReadAbort() throws Exception
    {
        k3po.finish();
    }
}
