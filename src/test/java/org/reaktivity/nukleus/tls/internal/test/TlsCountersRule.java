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
package org.reaktivity.nukleus.tls.internal.test;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.reaktivity.nukleus.tls.internal.TlsController;
import org.reaktivity.reaktor.test.ReaktorRule;

public class TlsCountersRule implements TestRule
{
    private final ReaktorRule reaktor;
    private TlsController controller;

    public TlsCountersRule(ReaktorRule reaktor)
    {
        this.reaktor = reaktor;
    }

    @Override
    public Statement apply(Statement base, Description description)
    {
        return new Statement()
        {
            @Override
            public void evaluate() throws Throwable
            {
                controller = reaktor.controller(TlsController.class);
                base.evaluate();
            }
        };
    }

    public long bytesRead(long routeId)
    {
        return controller.bytesRead(routeId);
    }

    public long bytesWritten(long routeId)
    {
        return controller.bytesWritten(routeId);
    }

    public long framesRead(long routeId)
    {
        return controller.framesRead(routeId);
    }

    public long framesWritten(long routeId)
    {
        return controller.framesWritten(routeId);
    }
}
