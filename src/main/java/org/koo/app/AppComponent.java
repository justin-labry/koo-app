/*
 * Copyright 2023-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.koo.app;

import org.onlab.packet.IpAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostService;
import org.onosproject.net.pi.runtime.PiAction;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Dictionary;
import java.util.Properties;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
        service = {SomeInterface.class},
        property = {
                "someProperty=Some Default String Value",
        })
public class AppComponent implements SomeInterface {

    private ApplicationId appId;
    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        log.info("koo.app Started");

        appId = coreService.registerApplication("org.koo.app");

        int flowPriority = 777;
        DeviceId deviceId= null;
        try {
            deviceId = DeviceId.deviceId(new URI("device:leaf1"));
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .piTableAction(
                        PiAction.builder()
                                .withId(SaiConstants.INGRESS_SRV6_ENDPOINT_END)
                               //.withParameters(actionParams)
                                .build())
                .build();


        final PiCriterion.Builder mySidCriterionBuilder = PiCriterion.builder();

        mySidCriterionBuilder.matchExact(SaiConstants.HDR_LOCATOR_BLOCK_LEN,32)
                        .matchExact(SaiConstants.HDR_LOCATOR_NODE_LEN, 16)
                        .matchExact(SaiConstants.HDR_FUNCTION_LEN, 16)
                        .matchExact(SaiConstants.HDR_ARGS_LEN, 16)
                        .matchTernary(SaiConstants.HDR_MY_SID, IpAddress.valueOf("2001:db8:cc:1::").getIp6Address().toOctets(),
                                IpAddress.valueOf("ffff:ffff:ffff:ffff::").getIp6Address().toOctets());

        final TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchPi(mySidCriterionBuilder.build())
                .build();

        PiAction piAction;

        flowRuleService.applyFlowRules(DefaultFlowRule.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .forTable(SaiConstants.INGRESS_SRV6_ENDPOINT_MY_SID_TABLE)
                .makePermanent()
                .withPriority(flowPriority)
                .forDevice(deviceId)
                .fromApp(appId)
                .build());
    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        log.info("koo.app Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

}