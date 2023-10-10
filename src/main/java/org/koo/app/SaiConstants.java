/*
 * Copyright 2017-present Open Networking Foundation
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

import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiCounterId;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiActionProfileId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiMeterId;

/**
 * Constants for sai pipeline.
 */
public final class SaiConstants {

    // hide default constructor
    private SaiConstants() {
    }

    // Header field IDs
    public static final PiMatchFieldId HDR_IN_PORT =
            PiMatchFieldId.of("in_port");
    public static final PiMatchFieldId HDR_DST_IP = PiMatchFieldId.of("dst_ip");
    public static final PiMatchFieldId HDR_LOCATOR_BLOCK_LEN =
            PiMatchFieldId.of("locator_block_len");
    public static final PiMatchFieldId HDR_MY_SID = PiMatchFieldId.of("my_sid");
    public static final PiMatchFieldId HDR_SIDLIST_ID =
            PiMatchFieldId.of("sidlist_id");
    public static final PiMatchFieldId HDR_IS_IP = PiMatchFieldId.of("is_ip");
    public static final PiMatchFieldId HDR_ECN = PiMatchFieldId.of("ecn");
    public static final PiMatchFieldId HDR_ARGS_LEN =
            PiMatchFieldId.of("args_len");
    public static final PiMatchFieldId HDR_LOCATOR_NODE_LEN =
            PiMatchFieldId.of("locator_node_len");
    public static final PiMatchFieldId HDR_IS_IPV6 =
            PiMatchFieldId.of("is_ipv6");
    public static final PiMatchFieldId HDR_IPV6_DST =
            PiMatchFieldId.of("ipv6_dst");
    public static final PiMatchFieldId HDR_VRF_ID = PiMatchFieldId.of("vrf_id");
    public static final PiMatchFieldId HDR_SRC_IPV6 =
            PiMatchFieldId.of("src_ipv6");
    public static final PiMatchFieldId HDR_L4_SRC_PORT =
            PiMatchFieldId.of("l4_src_port");
    public static final PiMatchFieldId HDR_OUT_PORT =
            PiMatchFieldId.of("out_port");
    public static final PiMatchFieldId HDR_SRC_IP = PiMatchFieldId.of("src_ip");
    public static final PiMatchFieldId HDR_ICMPV6_TYPE =
            PiMatchFieldId.of("icmpv6_type");
    public static final PiMatchFieldId HDR_DSCP = PiMatchFieldId.of("dscp");
    public static final PiMatchFieldId HDR_WCMP_GROUP_ID =
            PiMatchFieldId.of("wcmp_group_id");
    public static final PiMatchFieldId HDR_FUNCTION_LEN =
            PiMatchFieldId.of("function_len");
    public static final PiMatchFieldId HDR_IP_PROTOCOL =
            PiMatchFieldId.of("ip_protocol");
    public static final PiMatchFieldId HDR_ROUTER_INTERFACE_ID =
            PiMatchFieldId.of("router_interface_id");
    public static final PiMatchFieldId HDR_NEXTHOP_ID =
            PiMatchFieldId.of("nexthop_id");
    public static final PiMatchFieldId HDR_LOCAL_METADATA_SRV6_REMOVE_SRH =
            PiMatchFieldId.of("local_metadata.srv6.remove_srh");
    public static final PiMatchFieldId HDR_DST_IPV6 =
            PiMatchFieldId.of("dst_ipv6");
    public static final PiMatchFieldId HDR_TTL = PiMatchFieldId.of("ttl");
    public static final PiMatchFieldId HDR_DST_MAC =
            PiMatchFieldId.of("dst_mac");
    public static final PiMatchFieldId HDR_ETHER_TYPE =
            PiMatchFieldId.of("ether_type");
    public static final PiMatchFieldId HDR_NEIGHBOR_ID =
            PiMatchFieldId.of("neighbor_id");
    public static final PiMatchFieldId HDR_IS_IPV4 =
            PiMatchFieldId.of("is_ipv4");
    public static final PiMatchFieldId HDR_IPV4_DST =
            PiMatchFieldId.of("ipv4_dst");
    public static final PiMatchFieldId HDR_L4_DST_PORT =
            PiMatchFieldId.of("l4_dst_port");
    public static final PiMatchFieldId HDR_MIRROR_PORT =
            PiMatchFieldId.of("mirror_port");
    public static final PiMatchFieldId HDR_MIRROR_SESSION_ID =
            PiMatchFieldId.of("mirror_session_id");
    public static final PiMatchFieldId HDR_SRC_MAC =
            PiMatchFieldId.of("src_mac");
    // Table IDs
    public static final PiTableId INGRESS_SRV6_ENCAP_SIDLIST_TABLE =
            PiTableId.of("ingress.srv6_encap.sidlist_table");
    public static final PiTableId INGRESS_ROUTING_NEXTHOP_TABLE =
            PiTableId.of("ingress.routing.nexthop_table");
    public static final PiTableId INGRESS_MIRRORING_CLONE_MIRROR_SESSION_TABLE =
            PiTableId.of("ingress.mirroring_clone.mirror_session_table");
    public static final PiTableId INGRESS_L3_ADMIT_L3_ADMIT_TABLE =
            PiTableId.of("ingress.l3_admit.l3_admit_table");
    public static final PiTableId INGRESS_SRV6_ENCAP_SET_INNER_HEADERS =
            PiTableId.of("ingress.srv6_encap.set_inner_headers");
    public static final PiTableId EGRESS_ACL_EGRESS_ACL_EGRESS_TABLE =
            PiTableId.of("egress.acl_egress.acl_egress_table");
    public static final PiTableId INGRESS_SRV6_DECAP_DECAP_SRV6_HDR_TABLE =
            PiTableId.of("ingress.srv6_decap.decap_srv6_hdr_table");
    public static final PiTableId INGRESS_ACL_INGRESS_ACL_INGRESS_TABLE =
            PiTableId.of("ingress.acl_ingress.acl_ingress_table");
    public static final PiTableId INGRESS_ROUTING_WCMP_GROUP_TABLE =
            PiTableId.of("ingress.routing.wcmp_group_table");
    public static final PiTableId INGRESS_ROUTING_NEIGHBOR_TABLE =
            PiTableId.of("ingress.routing.neighbor_table");
    public static final PiTableId INGRESS_ROUTING_IPV6_TABLE =
            PiTableId.of("ingress.routing.ipv6_table");
    public static final PiTableId INGRESS_ACL_PRE_INGRESS_ACL_PRE_INGRESS_TABLE =
            PiTableId.of("ingress.acl_pre_ingress.acl_pre_ingress_table");
    public static final PiTableId INGRESS_ROUTING_ROUTER_INTERFACE_TABLE =
            PiTableId.of("ingress.routing.router_interface_table");
    public static final PiTableId INGRESS_SRV6_ENDPOINT_SRH_LENGTH =
            PiTableId.of("ingress.srv6_endpoint.srh_length");
    public static final PiTableId INGRESS_ROUTING_VRF_TABLE =
            PiTableId.of("ingress.routing.vrf_table");
    public static final PiTableId INGRESS_SRV6_ENDPOINT_MY_SID_TABLE =
            PiTableId.of("ingress.srv6_endpoint.my_sid_table");
    public static final PiTableId INGRESS_SRV6_ENDPOINT_REMOVE_SRH =
            PiTableId.of("ingress.srv6_endpoint.remove_srh");
    public static final PiTableId INGRESS_ROUTING_IPV4_TABLE =
            PiTableId.of("ingress.routing.ipv4_table");
    public static final PiTableId INGRESS_MIRRORING_CLONE_MIRROR_PORT_TO_PRE_SESSION_TABLE =
            PiTableId.of("ingress.mirroring_clone.mirror_port_to_pre_session_table");
    // Direct Counter IDs
    public static final PiCounterId EGRESS_ACL_EGRESS_ACL_EGRESS_COUNTER =
            PiCounterId.of("egress.acl_egress.acl_egress_counter");
    public static final PiCounterId INGRESS_ACL_INGRESS_ACL_INGRESS_COUNTER =
            PiCounterId.of("ingress.acl_ingress.acl_ingress_counter");
    public static final PiCounterId INGRESS_ACL_PRE_INGRESS_ACL_PRE_INGRESS_COUNTER =
            PiCounterId.of("ingress.acl_pre_ingress.acl_pre_ingress_counter");
    // Action IDs
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DX6_NEXTHOP =
            PiActionId.of("ingress.srv6_endpoint.end_dx6_nexthop");
    public static final PiActionId INGRESS_ACL_PRE_INGRESS_SET_VRF =
            PiActionId.of("ingress.acl_pre_ingress.set_vrf");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END =
            PiActionId.of("ingress.srv6_endpoint.end");
    public static final PiActionId INGRESS_ROUTING_TRAP =
            PiActionId.of("ingress.routing.trap");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_USD =
            PiActionId.of("ingress.srv6_endpoint.end_usd");
    public static final PiActionId INGRESS_MIRRORING_CLONE_MIRROR_AS_IPV4_ERSPAN =
            PiActionId.of("ingress.mirroring_clone.mirror_as_ipv4_erspan");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_INVALIDATE_SRH =
            PiActionId.of("ingress.srv6_endpoint.invalidate_srh");
    public static final PiActionId INGRESS_ACL_INGRESS_ACL_COPY =
            PiActionId.of("ingress.acl_ingress.acl_copy");
    public static final PiActionId INGRESS_ROUTING_DROP =
            PiActionId.of("ingress.routing.drop");
    public static final PiActionId NO_ACTION = PiActionId.of("NoAction");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_X_USD =
            PiActionId.of("ingress.srv6_endpoint.end_x_usd");
    public static final PiActionId INGRESS_ROUTING_SET_NEXTHOP =
            PiActionId.of("ingress.routing.set_nexthop");
    public static final PiActionId INGRESS_ROUTING_SET_WCMP_GROUP_ID =
            PiActionId.of("ingress.routing.set_wcmp_group_id");
    public static final PiActionId ACL_DROP = PiActionId.of("acl_drop");
    public static final PiActionId INGRESS_SRV6_ENCAP_SRV6_ENCAPS_0_RED =
            PiActionId.of("ingress.srv6_encap.srv6_encaps_0_red");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DT46 =
            PiActionId.of("ingress.srv6_endpoint.end_dt46");
    public static final PiActionId INGRESS_SRV6_ENCAP_SRV6_INSERT_1_RED =
            PiActionId.of("ingress.srv6_encap.srv6_insert_1_red");
    public static final PiActionId INGRESS_ROUTING_SET_INSERT_SIDLIST_NEXTHOP_ID =
            PiActionId.of("ingress.routing.set_insert_sidlist_nexthop_id");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DX4_NEXTHOP =
            PiActionId.of("ingress.srv6_endpoint.end_dx4_nexthop");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_PSP =
            PiActionId.of("ingress.srv6_endpoint.end_psp");
    public static final PiActionId INGRESS_ACL_INGRESS_ACL_MIRROR =
            PiActionId.of("ingress.acl_ingress.acl_mirror");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_X_PSP =
            PiActionId.of("ingress.srv6_endpoint.end_x_psp");
    public static final PiActionId INGRESS_SRV6_ENCAP_COPY_INNER_IPV4_TCP =
            PiActionId.of("ingress.srv6_encap.copy_inner_ipv4_tcp");
    public static final PiActionId INGRESS_SRV6_ENCAP_SRV6_INSERT_0_RED =
            PiActionId.of("ingress.srv6_encap.srv6_insert_0_red");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_SRV6_TRAP =
            PiActionId.of("ingress.srv6_endpoint.srv6_trap");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_X_FUNCTION =
            PiActionId.of("ingress.srv6_endpoint.end_x_function");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_U_A_NEXTHOP =
            PiActionId.of("ingress.srv6_endpoint.end_uA_nexthop");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_SRV6_DROP =
            PiActionId.of("ingress.srv6_endpoint.srv6_drop");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_SET_SRH_LEN =
            PiActionId.of("ingress.srv6_endpoint.set_srh_len");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_X_NEXTHOP =
            PiActionId.of("ingress.srv6_endpoint.end_x_nexthop");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_T_PSP =
            PiActionId.of("ingress.srv6_endpoint.end_t_psp");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DT4 =
            PiActionId.of("ingress.srv6_endpoint.end_dt4");
    public static final PiActionId INGRESS_ROUTING_SET_WCMP_GROUP_ID_AND_METADATA =
            PiActionId.of("ingress.routing.set_wcmp_group_id_and_metadata");
    public static final PiActionId INGRESS_SRV6_DECAP_SRV6_DECAP_V6_INNER_V4 =
            PiActionId.of("ingress.srv6_decap.srv6_decap_v6_inner_v4");
    public static final PiActionId INGRESS_ROUTING_SET_ENCAPS_SIDLIST_NEXTHOP_ID =
            PiActionId.of("ingress.routing.set_encaps_sidlist_nexthop_id");
    public static final PiActionId INGRESS_SRV6_ENCAP_COPY_INNER_IPV6_UDP =
            PiActionId.of("ingress.srv6_encap.copy_inner_ipv6_udp");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_FUNCTION =
            PiActionId.of("ingress.srv6_endpoint.end_function");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_T =
            PiActionId.of("ingress.srv6_endpoint.end_t");
    public static final PiActionId INGRESS_ROUTING_SET_DST_MAC =
            PiActionId.of("ingress.routing.set_dst_mac");
    public static final PiActionId INGRESS_ROUTING_SET_NEXTHOP_ID =
            PiActionId.of("ingress.routing.set_nexthop_id");
    public static final PiActionId INGRESS_ACL_INGRESS_ACL_FORWARD =
            PiActionId.of("ingress.acl_ingress.acl_forward");
    public static final PiActionId INGRESS_ROUTING_SET_IP_NEXTHOP =
            PiActionId.of("ingress.routing.set_ip_nexthop");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_U_N =
            PiActionId.of("ingress.srv6_endpoint.end_uN");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DT6 =
            PiActionId.of("ingress.srv6_endpoint.end_dt6");
    public static final PiActionId INGRESS_ROUTING_SET_NEXTHOP_ID_AND_METADATA =
            PiActionId.of("ingress.routing.set_nexthop_id_and_metadata");
    public static final PiActionId INGRESS_SRV6_DECAP_SRV6_DECAP_V6_INNER_V6 =
            PiActionId.of("ingress.srv6_decap.srv6_decap_v6_inner_v6");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_X_WCMP =
            PiActionId.of("ingress.srv6_endpoint.end_x_wcmp");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_B6_ENCAPS_RED =
            PiActionId.of("ingress.srv6_endpoint.end_b6_encaps_red");
    public static final PiActionId INGRESS_ACL_INGRESS_ACL_TRAP =
            PiActionId.of("ingress.acl_ingress.acl_trap");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_B6_INSERT_RED =
            PiActionId.of("ingress.srv6_endpoint.end_b6_insert_red");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_T_FUNCTION =
            PiActionId.of("ingress.srv6_endpoint.end_t_function");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DX6_WCMP =
            PiActionId.of("ingress.srv6_endpoint.end_dx6_wcmp");
    public static final PiActionId INGRESS_SRV6_ENCAP_COPY_INNER_IPV4_UDP =
            PiActionId.of("ingress.srv6_encap.copy_inner_ipv4_udp");
    public static final PiActionId INGRESS_ROUTING_SET_PORT_AND_SRC_MAC =
            PiActionId.of("ingress.routing.set_port_and_src_mac");
    public static final PiActionId INGRESS_L3_ADMIT_ADMIT_TO_L3 =
            PiActionId.of("ingress.l3_admit.admit_to_l3");
    public static final PiActionId INGRESS_SRV6_ENCAP_SRV6_ENCAPS_1_RED =
            PiActionId.of("ingress.srv6_encap.srv6_encaps_1_red");
    public static final PiActionId INGRESS_MIRRORING_CLONE_SET_PRE_SESSION =
            PiActionId.of("ingress.mirroring_clone.set_pre_session");
    public static final PiActionId INGRESS_ROUTING_NO_ACTION =
            PiActionId.of("ingress.routing.no_action");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_T_USD =
            PiActionId.of("ingress.srv6_endpoint.end_t_usd");
    public static final PiActionId INGRESS_SRV6_ENCAP_SRV6_ENCAPS_2_RED =
            PiActionId.of("ingress.srv6_encap.srv6_encaps_2_red");
    public static final PiActionId INGRESS_SRV6_ENDPOINT_END_DX4_WCMP =
            PiActionId.of("ingress.srv6_endpoint.end_dx4_wcmp");
    public static final PiActionId INGRESS_SRV6_ENCAP_COPY_INNER_IPV6_TCP =
            PiActionId.of("ingress.srv6_encap.copy_inner_ipv6_tcp");
    // Action Param IDs
    public static final PiActionParamId DST_IP = PiActionParamId.of("dst_ip");
    public static final PiActionParamId LEN = PiActionParamId.of("len");
    public static final PiActionParamId SIDLIST_ID =
            PiActionParamId.of("sidlist_id");
    public static final PiActionParamId SID0 = PiActionParamId.of("sid0");
    public static final PiActionParamId PORT = PiActionParamId.of("port");
    public static final PiActionParamId SID2 = PiActionParamId.of("sid2");
    public static final PiActionParamId ROUTE_METADATA =
            PiActionParamId.of("route_metadata");
    public static final PiActionParamId ID = PiActionParamId.of("id");
    public static final PiActionParamId VRF_ID = PiActionParamId.of("vrf_id");
    public static final PiActionParamId SRC_IP = PiActionParamId.of("src_ip");
    public static final PiActionParamId WCMP_GROUP_ID =
            PiActionParamId.of("wcmp_group_id");
    public static final PiActionParamId TUNNEL_SRC_IP =
            PiActionParamId.of("tunnel_src_ip");
    public static final PiActionParamId SID1 = PiActionParamId.of("sid1");
    public static final PiActionParamId TOS = PiActionParamId.of("tos");
    public static final PiActionParamId ROUTER_INTERFACE_ID =
            PiActionParamId.of("router_interface_id");
    public static final PiActionParamId NEXTHOP_ID =
            PiActionParamId.of("nexthop_id");
    public static final PiActionParamId TTL = PiActionParamId.of("ttl");
    public static final PiActionParamId DST_MAC = PiActionParamId.of("dst_mac");
    public static final PiActionParamId NEIGHBOR_ID =
            PiActionParamId.of("neighbor_id");
    public static final PiActionParamId MIRROR_SESSION_ID =
            PiActionParamId.of("mirror_session_id");
    public static final PiActionParamId SRC_MAC = PiActionParamId.of("src_mac");
    // Action Profile IDs
    public static final PiActionProfileId INGRESS_ROUTING_WCMP_GROUP_SELECTOR =
            PiActionProfileId.of("ingress.routing.wcmp_group_selector");
    // Packet Metadata IDs
    public static final PiPacketMetadataId SUBMIT_TO_INGRESS =
            PiPacketMetadataId.of("submit_to_ingress");
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final PiPacketMetadataId TARGET_EGRESS_PORT =
            PiPacketMetadataId.of("target_egress_port");
    public static final PiPacketMetadataId UNUSED_PAD =
            PiPacketMetadataId.of("unused_pad");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
    // Direct Meter IDs
    public static final PiMeterId INGRESS_ACL_INGRESS_ACL_INGRESS_METER =
            PiMeterId.of("ingress.acl_ingress.acl_ingress_meter");
}