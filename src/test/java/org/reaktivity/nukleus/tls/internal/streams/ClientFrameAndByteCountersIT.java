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
import static org.junit.Assert.assertTrue;
import static org.junit.rules.RuleChain.outerRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.DisableOnDebug;
import org.junit.rules.TestRule;
import org.junit.rules.Timeout;
import org.kaazing.k3po.junit.annotation.ScriptProperty;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.reaktivity.nukleus.tls.internal.TlsController;
import org.reaktivity.nukleus.tls.internal.test.TlsCountersRule;
import org.reaktivity.reaktor.test.ReaktorRule;

public class ClientFrameAndByteCountersIT
{
    private final K3poRule k3po = new K3poRule()
            .addScriptRoot("route", "org/reaktivity/specification/nukleus/tls/control/route")
            .addScriptRoot("client", "org/reaktivity/specification/nukleus/tls/streams")
            .addScriptRoot("server", "org/reaktivity/specification/tls");

    private final TestRule timeout = new DisableOnDebug(new Timeout(10, SECONDS));

    private final ReaktorRule reaktor = new ReaktorRule()
            .directory("target/nukleus-itests")
            .controller(TlsController.class::isAssignableFrom)
            .commandBufferCapacity(1024)
            .responseBufferCapacity(1024)
            .counterValuesBufferCapacity(1024)
            .nukleus("tls"::equals)
            .clean();

    private final TlsCountersRule counters = new TlsCountersRule(reaktor);

    @Rule
    public final TestRule chain = outerRule(reaktor).around(counters).around(k3po).around(timeout);

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
        long bytesRead = counters.bytesRead(0);
        long bytesWritten = counters.bytesWritten(0);
        long framesRead = counters.framesRead(0);
        long framesWritten = counters.framesWritten(0);

        // Values are not consistent across JVMs/Machines
        assertTrue(bytesRead > 10000);
        assertTrue(bytesWritten > 10000);
        assertTrue(framesRead > 3);
        assertTrue(framesWritten > 3);
    }

}
