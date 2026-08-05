#include "gobgp_client.hpp"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif // __GNUC__

//
// MinGW has quite weird definitions which clash with field names in gRPC bindinds
// We need to apply some trickery to avoid complilation errors: 
// https://github.com/pavel-odintsov/fastnetmon/issues/977
//

#ifdef _WIN32

// Save previous values of these defines
#pragma push_macro("interface")
#pragma push_macro("IN")
#pragma push_macro("OUT")

#undef interface
#undef IN
#undef OUT

#endif


#include "../gobgp_client/attribute.pb.h"

#ifdef _WIN32

// Restore original values of these defines
#pragma pop_macro("interface")
#pragma pop_macro("IN")
#pragma pop_macro("OUT")

#endif

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif // __GNUC__

#include "../all_logcpp_libraries.hpp"

#include "../fast_library.hpp"

unsigned int gobgp_client_connection_timeout = 5;

extern log4cpp::Category& logger;

GrpcClient::GrpcClient(std::shared_ptr<grpc::Channel> channel) : stub_(api::GoBgpService::NewStub(channel)) {

}


// Announce unicast or flow spec
bool GrpcClient::AnnounceCommonPrefix(dynamic_binary_buffer_t binary_nlri,
                                      std::vector<dynamic_binary_buffer_t> bgp_attributes,
                                      bool is_withdrawal,
                                      unsigned int afi,
                                      unsigned int safi) {
    // We're not going to free this memory and we delegate it to gRPC
    // but we need to tell about it to PVS
    //+V773:SUPPRESS, class:Path, namespace:api
    api::Path* current_path = new api::Path;

    if (is_withdrawal) {
        current_path->set_is_withdraw(true);
    }

    // We're not going to free this memory and we delegate it to gRPC
    // but we need to tell about it to PVS
    //+V773:SUPPRESS, class:Family, namespace:api
    auto route_family = new api::Family;

    if (afi == AFI_IP) {
        route_family->set_afi(api::Family::AFI_IP);
    } else if (afi == AFI_IP6) {
        route_family->set_afi(api::Family::AFI_IP6);
    } else {
        logger << log4cpp::Priority::ERROR << "Unknown AFI";
        return false;
    }

    if (safi == SAFI_UNICAST) {
        route_family->set_safi(api::Family::SAFI_UNICAST);
    } else if (safi == SAFI_FLOW_SPEC_UNICAST) {
        route_family->set_safi(api::Family::SAFI_FLOW_SPEC_UNICAST);
    } else {
        logger << log4cpp::Priority::ERROR << "Unknown SAFI";
        return false;
    }

    current_path->set_allocated_family(route_family);
    current_path->set_nlri_binary(binary_nlri.get_pointer(), binary_nlri.get_used_size());

    for (auto bgp_attribute : bgp_attributes) {
        current_path->add_pattrs_binary(bgp_attribute.get_pointer(), bgp_attribute.get_used_size());
    }

    api::AddPathRequest request;
    request.set_table_type(api::TableType::TABLE_TYPE_GLOBAL);
    request.set_allocated_path(current_path);

    grpc::ClientContext context;

    // Set timeout for API
    std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
    context.set_deadline(deadline);

    api::AddPathResponse response;

    // Don't be confused by name, it also can withdraw announces
    auto status = stub_->AddPath(&context, request, &response);

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "AddPath request to BGP daemon failed with code: " << status.error_code()
               << " message " << status.error_message();

        return false;
    }

    return true;
}

bool GrpcClient::AnnounceUnicastPrefixLowLevelIPv4(const IPv4UnicastAnnounce& unicast_ipv4_announce, bool is_withdrawal) {
    logger << log4cpp::Priority::INFO << "Send IPv4 " << (is_withdrawal ? "withdrawal " : "")
           << "unicast announce to BGP daemon: " << unicast_ipv4_announce.print();

    dynamic_binary_buffer_t binary_nlri;
    auto binary_nlri_generation_result = unicast_ipv4_announce.generate_nlri(binary_nlri);

    if (!binary_nlri_generation_result) {
        logger << log4cpp::Priority::ERROR << "Could not encode NLRI for IPv4 unicast announce due to unsuccessful error code";
        return false;
    }

    if (binary_nlri.get_used_size() == 0 or binary_nlri.get_pointer() == NULL) {
        logger << log4cpp::Priority::ERROR << "Could not encode NLRI for IPv4 unicast announce";
        return false;
    }

    std::vector<dynamic_binary_buffer_t> bgp_attributes;

    if (!unicast_ipv4_announce.get_attributes(bgp_attributes)) {
        logger << log4cpp::Priority::ERROR << "Could not get attributes for IPv4 unicast announce";
        return false;
    }

    if (bgp_attributes.size() == 0) {
        logger << log4cpp::Priority::ERROR << "We got zero number of attributes";
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "Got " << bgp_attributes.size() << " BGP attributes";

    return AnnounceCommonPrefix(binary_nlri, bgp_attributes, is_withdrawal, AFI_IP, SAFI_UNICAST);
}



bool GrpcClient::AnnounceUnicastPrefixLowLevelIPv6(const IPv6UnicastAnnounce& unicast_ipv6_announce, bool is_withdrawal) {
    logger << log4cpp::Priority::INFO << "Send IPv6 " << (is_withdrawal ? "withdrawal " : "")
           << "unicast announce to BGP daemon: " << unicast_ipv6_announce.print();

    // We need to prepare very fancy NLRI first: https://github.com/osrg/gobgp/issues/2673
    // To be more specific:
    // https://github.com/fujita/gobgp/blob/7e4d9a0e89b1fc5e4fc9865b7b6431a00dcb60e2/pkg/server/grpc_server_test.go#L48
    // And implementation details:
    // https://github.com/osrg/gobgp/blob/master/pkg/packet/bgp/bgp.go#L1501
    // https://github.com/osrg/gobgp/blob/master/pkg/packet/bgp/bgp.go#L1440

    dynamic_binary_buffer_t ipv6_nlri{};
    ipv6_nlri.set_buffer_size_in_bytes(256);

    if (!encode_ipv6_prefix(unicast_ipv6_announce.get_prefix(), ipv6_nlri)) {
        logger << log4cpp::Priority::ERROR << "Cannot encode prefix for IPv6 NLRI";
        return false;
    }

    // Normally, vector should be ordered in ascending order of attribute types
    // with the only exception for bgp_mp_reach_ipv6_attribute
    std::vector<dynamic_binary_buffer_t> bgp_attributes;

    dynamic_binary_buffer_t bgp_mp_reach_ipv6_attribute;
    bool craft_ipv6_mpreach_nlri_result =
        encode_ipv6_announces_into_bgp_mp_reach_attribute(unicast_ipv6_announce, bgp_mp_reach_ipv6_attribute);

    if (!craft_ipv6_mpreach_nlri_result) {
        logger << log4cpp::Priority::ERROR << "Can't encode MP reach NLRI for IPv6 announce";
        return false;
    }

    logger << log4cpp::Priority::DEBUG << "IPv6 MP reach NLRI attribute size is: " << bgp_mp_reach_ipv6_attribute.get_used_size();

    bgp_attributes.push_back(bgp_mp_reach_ipv6_attribute);

    bgp_attribute_origin origin_attr;

    dynamic_binary_buffer_t origin_as_binary_array;
    origin_as_binary_array.set_buffer_size_in_bytes(sizeof(origin_attr));
    origin_as_binary_array.append_data_as_object_ptr(&origin_attr);

    // It has attribute #1 and will be first in all the cases
    bgp_attributes.push_back(origin_as_binary_array);

    // TODO: this logic is copied as is from get_attributes() of IPv4 announces
    // We need to try ways to unify logic to craft such announces
    // AS Path should be here and it's #2
    if (unicast_ipv6_announce.as_path_asns.size() > 0) {
        // We have ASNs for AS_PATH attribute
        bgp_attribute_as_path_t bgp_attribute_as_path;

        // Populate attribute length
        bgp_attribute_as_path.attribute_length =
            sizeof(bgp_as_path_segment_element_t) + unicast_ipv6_announce.as_path_asns.size() * sizeof(uint32_t);

        logger << log4cpp::Priority::DEBUG << "AS_PATH attribute length: " << uint32_t(bgp_attribute_as_path.attribute_length);

        uint32_t as_path_attribute_full_length = sizeof(bgp_attribute_as_path_t) + bgp_attribute_as_path.attribute_length;

        logger << log4cpp::Priority::DEBUG << "AS_PATH attribute full length: " << as_path_attribute_full_length;

        dynamic_binary_buffer_t as_path_as_binary_array;
        as_path_as_binary_array.set_buffer_size_in_bytes(as_path_attribute_full_length);

        // Append attribute header
        as_path_as_binary_array.append_data_as_object_ptr(&bgp_attribute_as_path);

        bgp_as_path_segment_element_t bgp_as_path_segment_element;

        // Numbers of ASNs in list
        bgp_as_path_segment_element.path_segment_length = unicast_ipv6_announce.as_path_asns.size();

        logger << log4cpp::Priority::DEBUG
               << "AS_PATH segments number: " << uint32_t(bgp_as_path_segment_element.path_segment_length);

        // Append segment header
        as_path_as_binary_array.append_data_as_object_ptr(&bgp_as_path_segment_element);

        logger << log4cpp::Priority::DEBUG << "AS_PATH ASN number: " << unicast_ipv6_announce.as_path_asns.size();

        for (auto asn : unicast_ipv6_announce.as_path_asns) {
            // Append all ASNs in big endian encoding
            uint32_t asn_big_endian = fast_hton(asn);

            as_path_as_binary_array.append_data_as_object_ptr(&asn_big_endian);
        }

        if (as_path_as_binary_array.is_failed()) {
            logger << log4cpp::Priority::ERROR << "Issue with storing AS_PATH";
        }

        bgp_attributes.push_back(as_path_as_binary_array);
    }

    auto community_list = unicast_ipv6_announce.get_communities();

    if (!community_list.empty()) {
        // TODO: I copied this code from bgp_protocol.cpp from get_attributes() function. I think we can unify it

        // We have communities
        bgp_attribute_community_t bgp_attribute_community;

        // Each record has this of 4 bytes
        bgp_attribute_community.attribute_length = community_list.size() * sizeof(bgp_community_attribute_element_t);
        uint32_t community_attribute_full_length = sizeof(bgp_attribute_community_t) + bgp_attribute_community.attribute_length;

        dynamic_binary_buffer_t communities_list_as_binary_array;
        communities_list_as_binary_array.set_buffer_size_in_bytes(community_attribute_full_length);

        communities_list_as_binary_array.append_data_as_object_ptr(&bgp_attribute_community);

        for (auto bgp_community_element : community_list) {
            // Encode they in network byte order
            bgp_community_element.host_byte_order_to_network_byte_order();

            communities_list_as_binary_array.append_data_as_object_ptr(&bgp_community_element);
        }

        // Community is attribute #8
        bgp_attributes.push_back(communities_list_as_binary_array);
    }

    // Normally NLRI is empty for IPv6 announces but GoBGP uses pretty unusual approach to encode it described on top of this function
    return AnnounceCommonPrefix(ipv6_nlri, bgp_attributes, is_withdrawal, AFI_IP6, SAFI_UNICAST);
}

// Announce flowspec rule using GoBGP v4 typed protobuf API
bool GrpcClient::AnnounceFlowSpecPrefix(const flow_spec_rule_t& flow_spec_rule,
                                         bool is_withdrawal,
                                         unsigned int afi) {
    api::Path* current_path = new api::Path;
    current_path->set_is_withdraw(is_withdrawal);

    // Build typed NLRI on heap
    api::NLRI* nlri = new api::NLRI;
    api::FlowSpecNLRI* flow_spec_nlri = new api::FlowSpecNLRI;

    // Destination prefix (IPv4)
    if (flow_spec_rule.destination_subnet_ipv4_used) {
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecIPPrefix* ip_prefix = new api::FlowSpecIPPrefix;
        ip_prefix->set_type(1);
        subnet_cidr_mask_t dest = flow_spec_rule.destination_subnet_ipv4;
        ip_prefix->set_prefix(convert_ip_as_uint_to_string(dest.subnet_address));
        ip_prefix->set_prefix_len(dest.cidr_prefix_length);
        rule->set_allocated_ip_prefix(ip_prefix);
    }

    // Destination prefix (IPv6)
    if (flow_spec_rule.destination_subnet_ipv6_used) {
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecIPPrefix* ip_prefix = new api::FlowSpecIPPrefix;
        ip_prefix->set_type(1);
        ip_prefix->set_prefix(print_ipv6_address(flow_spec_rule.destination_subnet_ipv6.subnet_address));
        ip_prefix->set_prefix_len(flow_spec_rule.destination_subnet_ipv6.cidr_prefix_length);
        rule->set_allocated_ip_prefix(ip_prefix);
    }

    // Source prefix (IPv4)
    if (flow_spec_rule.source_subnet_ipv4_used) {
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecIPPrefix* ip_prefix = new api::FlowSpecIPPrefix;
        ip_prefix->set_type(2);
        subnet_cidr_mask_t src = flow_spec_rule.source_subnet_ipv4;
        ip_prefix->set_prefix(convert_ip_as_uint_to_string(src.subnet_address));
        ip_prefix->set_prefix_len(src.cidr_prefix_length);
        rule->set_allocated_ip_prefix(ip_prefix);
    }

    // Source prefix (IPv6)
    if (flow_spec_rule.source_subnet_ipv6_used) {
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecIPPrefix* ip_prefix = new api::FlowSpecIPPrefix;
        ip_prefix->set_type(2);
        ip_prefix->set_prefix(print_ipv6_address(flow_spec_rule.source_subnet_ipv6.subnet_address));
        ip_prefix->set_prefix_len(flow_spec_rule.source_subnet_ipv6.cidr_prefix_length);
        rule->set_allocated_ip_prefix(ip_prefix);
    }

    // Helper lambda to add a numeric component
    auto add_component = [&](uint32_t comp_type, const std::vector<uint16_t>& values) {
        if (values.empty()) return;
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecComponent* component = new api::FlowSpecComponent;
        component->set_type(comp_type);
        for (size_t i = 0; i < values.size(); i++) {
            api::FlowSpecComponentItem* item = component->add_items();
            uint8_t op = 0x01; // OP_EQ
            if (i == values.size() - 1) op |= 0x80; // OP_END
            item->set_op(op);
            item->set_value(values[i]);
        }
        rule->set_allocated_component(component);
    };

    // IP protocols
    if (flow_spec_rule.protocols.size() > 0) {
        api::FlowSpecRule* rule = flow_spec_nlri->add_rules();
        api::FlowSpecComponent* component = new api::FlowSpecComponent;
        component->set_type(3);
        for (size_t i = 0; i < flow_spec_rule.protocols.size(); i++) {
            api::FlowSpecComponentItem* item = component->add_items();
            uint8_t op = 0x01;
            if (i == flow_spec_rule.protocols.size() - 1) op |= 0x80;
            item->set_op(op);
            item->set_value(static_cast<uint8_t>(
                static_cast<std::underlying_type<ip_protocol_t>::type>(flow_spec_rule.protocols[i])));
        }
        rule->set_allocated_component(component);
    }

    add_component(5, flow_spec_rule.destination_ports);
    add_component(6, flow_spec_rule.source_ports);

    nlri->set_allocated_flow_spec(flow_spec_nlri);
    current_path->set_allocated_nlri(nlri);

    // Build family on heap
    api::Family* route_family = new api::Family;
    if (afi == AFI_IP) {
        route_family->set_afi(api::Family::AFI_IP);
    } else if (afi == AFI_IP6) {
        route_family->set_afi(api::Family::AFI_IP6);
    } else {
        logger << log4cpp::Priority::ERROR << "Unknown AFI for flowspec";
        delete current_path;
        return false;
    }
    route_family->set_safi(api::Family::SAFI_FLOW_SPEC_UNICAST);
    current_path->set_allocated_family(route_family);

    // Origin attribute (INCOMPLETE)
    {
        api::Attribute* attr = current_path->add_pattrs();
        api::OriginAttribute* origin = new api::OriginAttribute;
        origin->set_origin(2); // BGP_ORIGIN_INCOMPLETE
        attr->set_allocated_origin(origin);
    }

    // Extended community action (only for announcements)
    if (!is_withdrawal) {
        bgp_flow_spec_action_t bgp_action = flow_spec_rule.get_action();
        api::Attribute* ext_attr = current_path->add_pattrs();
        api::ExtendedCommunitiesAttribute* ext_comms = new api::ExtendedCommunitiesAttribute;

        switch (bgp_action.get_type()) {
            case bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_DISCARD: {
                api::ExtendedCommunity* comm = ext_comms->add_communities();
                api::TrafficRateExtended* rate = new api::TrafficRateExtended;
                rate->set_rate(0.0f);
                comm->set_allocated_traffic_rate(rate);
                break;
            }
            case bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_RATE_LIMIT: {
                api::ExtendedCommunity* comm = ext_comms->add_communities();
                api::TrafficRateExtended* rate = new api::TrafficRateExtended;
                rate->set_rate(static_cast<float>(bgp_action.get_rate_limit()));
                comm->set_allocated_traffic_rate(rate);
                break;
            }
            case bgp_flow_spec_action_types_t::FLOW_SPEC_ACTION_REDIRECT: {
                api::ExtendedCommunity* comm = ext_comms->add_communities();
                api::RedirectTwoOctetAsSpecificExtended* redirect = new api::RedirectTwoOctetAsSpecificExtended;
                redirect->set_asn(0);
                redirect->set_local_admin(0);
                comm->set_allocated_redirect_two_octet_as_specific(redirect);
                break;
            }
            default:
                break;
        }

        ext_attr->set_allocated_extended_communities(ext_comms);
    }

    // Send request
    api::AddPathRequest request;
    request.set_table_type(api::TableType::TABLE_TYPE_GLOBAL);
    request.set_allocated_path(current_path);

    grpc::ClientContext context;
    std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + std::chrono::seconds(gobgp_client_connection_timeout);
    context.set_deadline(deadline);

    api::AddPathResponse response;
    auto status = stub_->AddPath(&context, request, &response);

    if (!status.ok()) {
        logger << log4cpp::Priority::ERROR << "AddPath request to BGP daemon failed with code: " << status.error_code()
               << " message " << status.error_message();
        return false;
    }

    return true;
}

