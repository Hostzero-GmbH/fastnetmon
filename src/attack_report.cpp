#include "attack_report.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <boost/circular_buffer.hpp>

#include "all_logcpp_libraries.hpp"
#include "fast_library.hpp"
#include "fast_platform.hpp"
#include "nlohmann/json.hpp"

extern log4cpp::Category& logger;

extern std::map<std::string, std::string> configuration_map;
extern FastnetmonPlatformConfigurtion fastnetmon_platform_configuration;

// Global instances
attack_report_config_t global_attack_report_config;

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

void read_attack_report_config() {
    if (configuration_map.count("pcap_dump") != 0) {
        global_attack_report_config.pcap_dump = configuration_map["pcap_dump"] == "on";
    }

    if (configuration_map.count("pcap_dump_linktype") != 0) {
        int val = convert_string_to_integer(configuration_map["pcap_dump_linktype"]);
        if (val > 0) {
            global_attack_report_config.pcap_dump_linktype = static_cast<uint32_t>(val);
        }
    }

    if (configuration_map.count("attack_report") != 0) {
        global_attack_report_config.attack_report = configuration_map["attack_report"] == "on";
    }

    if (configuration_map.count("top_talkers_max_entries") != 0) {
        int val = convert_string_to_integer(configuration_map["top_talkers_max_entries"]);
        if (val > 0) {
            global_attack_report_config.top_talkers_max_entries = static_cast<unsigned int>(val);
        }
    }
}

// ---------------------------------------------------------------------------
// PCAP dump writer
// ---------------------------------------------------------------------------

bool write_pcap_dump(const std::string& file_path,
                     const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer,
                     uint32_t linktype) {
    if (raw_packets_buffer.empty()) {
        return false;
    }

    int filedesc = ::open(file_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (filedesc < 0) {
        logger << log4cpp::Priority::ERROR << "Cannot open pcap dump file " << file_path << ": " << strerror(errno);
        return false;
    }

    // Write PCAP global header
    fastnetmon_pcap_file_header_t pcap_header;
    // snaplen matches the fixed_size_packet_storage_t payload capacity
    fill_pcap_header(&pcap_header, 2048);
    pcap_header.linktype = linktype;

    ssize_t written = write(filedesc, &pcap_header, sizeof(pcap_header));
    if (written != static_cast<ssize_t>(sizeof(pcap_header))) {
        logger << log4cpp::Priority::ERROR << "Cannot write pcap header to " << file_path;
        ::close(filedesc);
        ::unlink(file_path.c_str());
        return false;
    }

    // Write each packet
    for (const auto& raw_pkt : raw_packets_buffer) {
        // Write packet header
        written = write(filedesc, &raw_pkt.packet_metadata, sizeof(raw_pkt.packet_metadata));
        if (written != static_cast<ssize_t>(sizeof(raw_pkt.packet_metadata))) {
            logger << log4cpp::Priority::ERROR << "Error writing pcap packet header to " << file_path;
            break;
        }

        // Write packet payload (only incl_len bytes)
        unsigned int incl_len = raw_pkt.packet_metadata.incl_len;
        if (incl_len > 0) {
            if (incl_len > 2048) {
                incl_len = 2048;
            }
            written = write(filedesc, raw_pkt.packet_payload, incl_len);
            if (written != static_cast<ssize_t>(incl_len)) {
                logger << log4cpp::Priority::ERROR << "Error writing pcap packet payload to " << file_path;
                break;
            }
        }
    }

    ::close(filedesc);
    return true;
}

// ---------------------------------------------------------------------------
// Top talkers aggregation
// ---------------------------------------------------------------------------

std::vector<top_talker_entry_t> aggregate_top_talkers(
    const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
    direction_t attack_direction,
    unsigned int max_entries) {
    if (simple_packets_buffer.empty() || max_entries == 0) {
        return {};
    }

    // Map IP string -> {packets, bytes}
    std::map<std::string, top_talker_entry_t> talker_map;

    for (const auto& pkt : simple_packets_buffer) {
        std::string ip;
        uint64_t pkt_bytes = pkt.length;

        // For incoming attacks, the source IP is the attacker.
        // For outgoing attacks, the destination IP is the interesting target.
        if (attack_direction == OUTGOING) {
            if (pkt.ip_protocol_version == 4) {
                ip = convert_ip_as_uint_to_string(pkt.dst_ip);
            } else {
                ip = print_ipv6_address(pkt.dst_ipv6);
            }
        } else {
            // INCOMING, OTHER
            if (pkt.ip_protocol_version == 4) {
                ip = convert_ip_as_uint_to_string(pkt.src_ip);
            } else {
                ip = print_ipv6_address(pkt.src_ipv6);
            }
        }

        if (ip.empty()) {
            continue;
        }

        talker_map[ip].ip = ip;
        talker_map[ip].packets += (pkt.number_of_packets > 0 ? pkt.number_of_packets : 1);
        talker_map[ip].bytes += pkt_bytes;
    }

    // Sort by packets descending, take top N
    std::vector<top_talker_entry_t> sorted;
    sorted.reserve(talker_map.size());
    for (const auto& kv : talker_map) {
        sorted.push_back(kv.second);
    }

    std::sort(sorted.begin(), sorted.end(), [](const top_talker_entry_t& a, const top_talker_entry_t& b) {
        return a.packets > b.packets;
    });

    if (sorted.size() > max_entries) {
        sorted.resize(max_entries);
    }

    return sorted;
}

// ---------------------------------------------------------------------------
// Attack classification
// ---------------------------------------------------------------------------

static std::string get_classification_name(attack_classification_t type) {
    switch (type) {
    case attack_classification_t::SYN_FLOOD:
        return "syn_flood";
    case attack_classification_t::UDP_FLOOD:
        return "udp_flood";
    case attack_classification_t::DNS_AMPLIFICATION:
        return "dns_amplification";
    case attack_classification_t::NTP_AMPLIFICATION:
        return "ntp_amplification";
    case attack_classification_t::ICMP_FLOOD:
        return "icmp_flood";
    case attack_classification_t::ACK_FLOOD:
        return "ack_flood";
    case attack_classification_t::UDP_FRAGMENT_FLOOD:
        return "udp_fragment_flood";
    case attack_classification_t::MIXED:
        return "mixed";
    case attack_classification_t::SSDP_AMPLIFICATION:
        return "ssdp_amplification";
    case attack_classification_t::SNMP_AMPLIFICATION:
        return "snmp_amplification";
    case attack_classification_t::CHARGEN_AMPLIFICATION:
        return "chargen_amplification";
    default:
        return "unknown";
    }
}

attack_classification_result_t classify_attack(const subnet_counter_t& traffic_counters,
                                               direction_t attack_direction,
                                               const boost::circular_buffer<simple_packet_t>& simple_packets_buffer) {
    attack_classification_result_t result;

    // Protocol distribution from traffic counters (direction aware)
    uint64_t tcp_pps = 0, udp_pps = 0, icmp_pps = 0, total_pps = 0;
    if (attack_direction == INCOMING || attack_direction == OTHER) {
        tcp_pps = traffic_counters.tcp.in_packets;
        udp_pps = traffic_counters.udp.in_packets;
        icmp_pps = traffic_counters.icmp.in_packets;
    }
    if (attack_direction == OUTGOING || attack_direction == OTHER) {
        tcp_pps = std::max(tcp_pps, traffic_counters.tcp.out_packets);
        udp_pps = std::max(udp_pps, traffic_counters.udp.out_packets);
        icmp_pps = std::max(icmp_pps, traffic_counters.icmp.out_packets);
    }
    total_pps = tcp_pps + udp_pps + icmp_pps;

    if (total_pps > 0) {
        result.tcp_ratio = static_cast<double>(tcp_pps) / static_cast<double>(total_pps);
        result.udp_ratio = static_cast<double>(udp_pps) / static_cast<double>(total_pps);
        result.icmp_ratio = static_cast<double>(icmp_pps) / static_cast<double>(total_pps);
    }

    // Analyze packet sample for port heuristics, TCP flags, unique sources
    uint64_t syn_count = 0;
    uint64_t tcp_count = 0;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    bool has_dst_port_53 = false;
    bool has_dst_port_123 = false;
    bool has_dst_port_1900 = false;
    bool has_dst_port_161 = false;
    bool has_dst_port_19 = false;
    bool has_fragmented = false;
    std::set<std::string> unique_src_ips;
    std::set<uint16_t> unique_dst_ports;

    for (const auto& pkt : simple_packets_buffer) {
        total_packets++;
        total_bytes += pkt.length;

        if (pkt.protocol == IPPROTO_TCP) {
            tcp_count++;
            if (extract_bit_value(pkt.flags, TCP_SYN_FLAG_SHIFT)) {
                syn_count++;
            }
        }

        // Source IP (direction-aware)
        std::string src_ip;
        if (attack_direction == OUTGOING) {
            src_ip = (pkt.ip_protocol_version == 4)
                ? convert_ip_as_uint_to_string(pkt.dst_ip)
                : print_ipv6_address(pkt.dst_ipv6);
        } else {
            src_ip = (pkt.ip_protocol_version == 4)
                ? convert_ip_as_uint_to_string(pkt.src_ip)
                : print_ipv6_address(pkt.src_ipv6);
        }
        if (!src_ip.empty()) {
            unique_src_ips.insert(src_ip);
        }

        // Destination ports
        unique_dst_ports.insert(pkt.destination_port);

        // Port heuristics (only for UDP)
        if (pkt.protocol == IPPROTO_UDP) {
            if (pkt.destination_port == 53) {
                has_dst_port_53 = true;
            } else if (pkt.destination_port == 123) {
                has_dst_port_123 = true;
            } else if (pkt.destination_port == 1900) {
                has_dst_port_1900 = true;
            } else if (pkt.destination_port == 161) {
                has_dst_port_161 = true;
            } else if (pkt.destination_port == 19) {
                has_dst_port_19 = true;
            }
        }

        // Fragmented packets
        if (pkt.ip_fragmented) {
            has_fragmented = true;
        }
    }

    result.unique_src_ips = unique_src_ips.size();
    result.unique_dst_ports = unique_dst_ports.size();
    result.avg_packet_size = (total_packets > 0) ? static_cast<double>(total_bytes) / static_cast<double>(total_packets) : 0.0;

    // Classification heuristics
    double syn_ratio = (tcp_count > 0) ? static_cast<double>(syn_count) / static_cast<double>(tcp_count) : 0.0;

    std::stringstream desc;

    if (result.udp_ratio > 0.5 && has_dst_port_53) {
        result.type = attack_classification_t::DNS_AMPLIFICATION;
        desc << "DNS amplification: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, port 53";
    } else if (result.udp_ratio > 0.5 && has_dst_port_123) {
        result.type = attack_classification_t::NTP_AMPLIFICATION;
        desc << "NTP amplification: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, port 123";
    } else if (result.udp_ratio > 0.5 && has_dst_port_1900) {
        result.type = attack_classification_t::SSDP_AMPLIFICATION;
        desc << "SSDP amplification: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, port 1900";
    } else if (result.udp_ratio > 0.5 && has_dst_port_161) {
        result.type = attack_classification_t::SNMP_AMPLIFICATION;
        desc << "SNMP amplification: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, port 161";
    } else if (result.udp_ratio > 0.5 && has_dst_port_19) {
        result.type = attack_classification_t::CHARGEN_AMPLIFICATION;
        desc << "CHARGEN amplification: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, port 19";
    } else if (result.udp_ratio > 0.5 && has_fragmented) {
        result.type = attack_classification_t::UDP_FRAGMENT_FLOOD;
        desc << "UDP fragment flood: UDP " << static_cast<int>(result.udp_ratio * 100) << "%, fragmented";
    } else if (result.udp_ratio > 0.5) {
        result.type = attack_classification_t::UDP_FLOOD;
        desc << "UDP flood: UDP " << static_cast<int>(result.udp_ratio * 100) << "%";
    } else if (result.tcp_ratio > 0.5 && syn_ratio > 0.8) {
        result.type = attack_classification_t::SYN_FLOOD;
        desc << "SYN flood: TCP " << static_cast<int>(result.tcp_ratio * 100) << "%, SYN " << static_cast<int>(syn_ratio * 100) << "%";
    } else if (result.tcp_ratio > 0.5) {
        // TCP but not mostly SYN -> likely ACK flood or mixed TCP
        result.type = attack_classification_t::ACK_FLOOD;
        desc << "TCP flood (non-SYN): TCP " << static_cast<int>(result.tcp_ratio * 100) << "%, SYN " << static_cast<int>(syn_ratio * 100) << "%";
    } else if (result.icmp_ratio > 0.5) {
        result.type = attack_classification_t::ICMP_FLOOD;
        desc << "ICMP flood: ICMP " << static_cast<int>(result.icmp_ratio * 100) << "%";
    } else if (result.icmp_ratio > 0.0 || result.udp_ratio > 0.0 || result.tcp_ratio > 0.0) {
        result.type = attack_classification_t::MIXED;
        desc << "Mixed: TCP " << static_cast<int>(result.tcp_ratio * 100) << "%, UDP " << static_cast<int>(result.udp_ratio * 100)
             << "%, ICMP " << static_cast<int>(result.icmp_ratio * 100) << "%";
    }

    desc << ", " << result.unique_src_ips << " unique sources, avg packet " << static_cast<int>(result.avg_packet_size) << " bytes";
    result.description = desc.str();

    return result;
}

// ---------------------------------------------------------------------------
// Report file path helpers
// ---------------------------------------------------------------------------

std::string get_attack_report_file_path(const std::string& client_ip_as_string, const attack_details_t& current_attack) {
    std::string ban_ts = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string uuid = current_attack.get_attack_uuid_as_string();
    return fastnetmon_platform_configuration.attack_details_folder + "/" + client_ip_as_string + "_" + ban_ts + "_" + uuid + ".json";
}

std::string get_attack_pcap_file_path(const std::string& client_ip_as_string, const attack_details_t& current_attack) {
    std::string ban_ts = print_time_t_in_fastnetmon_format(current_attack.ban_timestamp);
    std::string uuid = current_attack.get_attack_uuid_as_string();
    return fastnetmon_platform_configuration.attack_details_folder + "/" + client_ip_as_string + "_" + ban_ts + "_" + uuid + ".pcap";
}

// ---------------------------------------------------------------------------
// Traffic counters to JSON (self-contained, mirrors fastnetmon_logic.cpp)
// ---------------------------------------------------------------------------

static bool serialize_traffic_counters_to_json_local(const subnet_counter_t& traffic_counters, nlohmann::json& json_details) {
    try {
        json_details["total_incoming_traffic"] = traffic_counters.total.in_bytes;
        json_details["total_incoming_traffic_bits"] = traffic_counters.total.in_bytes * 8;
        json_details["total_outgoing_traffic"] = traffic_counters.total.out_bytes;
        json_details["total_outgoing_traffic_bits"] = traffic_counters.total.out_bytes * 8;
        json_details["total_incoming_pps"] = traffic_counters.total.in_packets;
        json_details["total_outgoing_pps"] = traffic_counters.total.out_packets;
        json_details["total_incoming_flows"] = traffic_counters.in_flows;
        json_details["total_outgoing_flows"] = traffic_counters.out_flows;
        json_details["incoming_dropped_traffic"] = traffic_counters.dropped.in_bytes;
        json_details["incoming_dropped_traffic_bits"] = traffic_counters.dropped.in_bytes * 8;
        json_details["outgoing_dropped_traffic"] = traffic_counters.dropped.out_bytes;
        json_details["outgoing_dropped_traffic_bits"] = traffic_counters.dropped.out_bytes * 8;
        json_details["incoming_dropped_pps"] = traffic_counters.dropped.in_packets;
        json_details["outgoing_dropped_pps"] = traffic_counters.dropped.out_packets;
        json_details["incoming_ip_fragmented_traffic"] = traffic_counters.fragmented.in_bytes;
        json_details["incoming_ip_fragmented_traffic_bits"] = traffic_counters.fragmented.in_bytes * 8;
        json_details["outgoing_ip_fragmented_traffic"] = traffic_counters.fragmented.out_bytes;
        json_details["outgoing_ip_fragmented_traffic_bits"] = traffic_counters.fragmented.out_bytes * 8;
        json_details["incoming_ip_fragmented_pps"] = traffic_counters.fragmented.in_packets;
        json_details["outgoing_ip_fragmented_pps"] = traffic_counters.fragmented.out_packets;
        json_details["incoming_tcp_traffic"] = traffic_counters.tcp.in_bytes;
        json_details["incoming_tcp_traffic_bits"] = traffic_counters.tcp.in_bytes * 8;
        json_details["outgoing_tcp_traffic"] = traffic_counters.tcp.out_bytes;
        json_details["outgoing_tcp_traffic_bits"] = traffic_counters.tcp.out_bytes * 8;
        json_details["incoming_tcp_pps"] = traffic_counters.tcp.in_packets;
        json_details["outgoing_tcp_pps"] = traffic_counters.tcp.out_packets;
        json_details["incoming_syn_tcp_traffic"] = traffic_counters.tcp_syn.in_bytes;
        json_details["incoming_syn_tcp_traffic_bits"] = traffic_counters.tcp_syn.in_bytes * 8;
        json_details["outgoing_syn_tcp_traffic"] = traffic_counters.tcp_syn.out_bytes;
        json_details["outgoing_syn_tcp_traffic_bits"] = traffic_counters.tcp_syn.out_bytes * 8;
        json_details["incoming_syn_tcp_pps"] = traffic_counters.tcp_syn.in_packets;
        json_details["outgoing_syn_tcp_pps"] = traffic_counters.tcp_syn.out_packets;
        json_details["incoming_udp_traffic"] = traffic_counters.udp.in_bytes;
        json_details["incoming_udp_traffic_bits"] = traffic_counters.udp.in_bytes * 8;
        json_details["outgoing_udp_traffic"] = traffic_counters.udp.out_bytes;
        json_details["outgoing_udp_traffic_bits"] = traffic_counters.udp.out_bytes * 8;
        json_details["incoming_udp_pps"] = traffic_counters.udp.in_packets;
        json_details["outgoing_udp_pps"] = traffic_counters.udp.out_packets;
        json_details["incoming_icmp_traffic"] = traffic_counters.icmp.in_bytes;
        json_details["incoming_icmp_traffic_bits"] = traffic_counters.icmp.in_bytes * 8;
        json_details["outgoing_icmp_traffic"] = traffic_counters.icmp.out_bytes;
        json_details["outgoing_icmp_traffic_bits"] = traffic_counters.icmp.out_bytes * 8;
        json_details["incoming_icmp_pps"] = traffic_counters.icmp.in_packets;
        json_details["outgoing_icmp_pps"] = traffic_counters.icmp.out_packets;
    } catch (...) {
        logger << log4cpp::Priority::ERROR << "Exception in attack report traffic counters serialization";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Attack report JSON writer
// ---------------------------------------------------------------------------

bool write_attack_report(const std::string& client_ip_as_string,
                         const attack_details_t& current_attack,
                         const std::vector<top_talker_entry_t>& top_talkers,
                         const attack_classification_result_t& classification,
                         const std::vector<timeline_event_t>& timeline,
                         const std::string& pcap_file_path,
                         const std::string& status) {
    if (!global_attack_report_config.attack_report) {
        return false;
    }

    std::string file_path = get_attack_report_file_path(client_ip_as_string, current_attack);

    // Try reading existing report first (for updates)
    nlohmann::json report;
    std::ifstream existing(file_path);
    if (existing.is_open()) {
        try {
            existing >> report;
        } catch (...) {
            // If reading fails, start fresh
        }
    }

    // Set fields on first write (not overwritten on updates)
    if (!report.contains("attack_uuid")) {
        report["attack_uuid"] = current_attack.get_attack_uuid_as_string();
        report["ip"] = client_ip_as_string;
        report["ipv6"] = current_attack.ipv6;
        report["host_group"] = current_attack.host_group;
        report["detection_time"] = static_cast<uint64_t>(current_attack.detection_time);
        report["ban_time"] = static_cast<uint64_t>(current_attack.ban_timestamp);
        report["detection_source"] = (current_attack.attack_detection_source == attack_detection_source_t::Manual)
            ? "manual" : "automatic";
        report["attack_direction"] = get_direction_name(current_attack.attack_direction);
        report["attack_severity"] = (current_attack.attack_severity == ATTACK_SEVERITY_LOW) ? "low"
            : (current_attack.attack_severity == ATTACK_SEVERITY_HIGH) ? "high" : "middle";
        report["attack_power_pps"] = current_attack.attack_power;
        report["max_attack_power_pps"] = current_attack.max_attack_power;
        report["attack_protocol"] = get_printable_protocol_name(current_attack.attack_protocol);
        report["ban_action"] = (current_attack.ban_action == ban_action_t::BAN_ACTION_FLOW_SPEC_DISCARD) ? "flow_spec_discard"
            : (current_attack.ban_action == ban_action_t::BAN_ACTION_FLOW_SPEC_RATE_LIMIT) ? "flow_spec_rate_limit"
            : "blackhole";

        if (current_attack.ban_action == ban_action_t::BAN_ACTION_FLOW_SPEC_RATE_LIMIT) {
            report["flow_spec_rate_limit"] = current_attack.flow_spec_rate_limit;
        }

        // Traffic counters
        nlohmann::json tc_json;
        if (serialize_traffic_counters_to_json_local(current_attack.traffic_counters, tc_json)) {
            report["traffic_counters"] = tc_json;
        }

        // PCAP file path
        if (!pcap_file_path.empty()) {
            report["pcap_file"] = pcap_file_path;
        }

        // Top talkers
        if (!top_talkers.empty()) {
            nlohmann::json tt_json = nlohmann::json::array();
            for (const auto& tt : top_talkers) {
                nlohmann::json entry;
                entry["ip"] = tt.ip;
                entry["packets"] = tt.packets;
                entry["bytes"] = tt.bytes;
                tt_json.push_back(entry);
            }
            report["top_talkers"] = tt_json;
        }

        // Classification
        if (classification.type != attack_classification_t::UNKNOWN) {
            nlohmann::json cl_json;
            cl_json["type"] = get_classification_name(classification.type);
            cl_json["description"] = classification.description;
            cl_json["tcp_ratio"] = classification.tcp_ratio;
            cl_json["udp_ratio"] = classification.udp_ratio;
            cl_json["icmp_ratio"] = classification.icmp_ratio;
            cl_json["unique_src_ips"] = classification.unique_src_ips;
            cl_json["unique_dst_ports"] = classification.unique_dst_ports;
            cl_json["avg_packet_size"] = classification.avg_packet_size;
            report["classification"] = cl_json;
        }
    }

    // Unban time (only set on unban, not overwritten)
    if (status == "unbanned" || status == "completed") {
        if (!report.contains("unban_time")) {
            report["unban_time"] = static_cast<uint64_t>(std::time(nullptr));
        }
    }

    if (status == "completed") {
        if (!report.contains("verification_time")) {
            report["verification_time"] = static_cast<uint64_t>(std::time(nullptr));
        }
    }

    // Timeline events
    if (!timeline.empty()) {
        nlohmann::json tl_json = report.contains("timeline") ? report["timeline"] : nlohmann::json::array();
        for (const auto& ev : timeline) {
            nlohmann::json entry;
            entry["event"] = ev.event_type;
            entry["timestamp"] = static_cast<uint64_t>(ev.timestamp);
            entry["details"] = ev.details;
            tl_json.push_back(entry);
        }
        report["timeline"] = tl_json;
    }

    // Status
    if (!status.empty()) {
        report["status"] = status;
    }

    // Write file
    std::ofstream out(file_path);
    if (!out.is_open()) {
        logger << log4cpp::Priority::ERROR << "Cannot open attack report file for writing: " << file_path;
        return false;
    }

    out << report.dump(2) << std::endl;
    out.close();

    return true;
}

// ---------------------------------------------------------------------------
// Append a single timeline event to an existing report
// ---------------------------------------------------------------------------

bool append_timeline_event_to_report(const std::string& client_ip_as_string,
                                     const attack_details_t& current_attack,
                                     const std::string& event_type,
                                     const std::string& details,
                                     const std::string& status) {
    if (!global_attack_report_config.attack_report) {
        return false;
    }

    std::vector<timeline_event_t> timeline;
    timeline_event_t ev;
    ev.event_type = event_type;
    ev.timestamp = std::time(nullptr);
    ev.details = details;
    timeline.push_back(ev);

    return write_attack_report(client_ip_as_string, current_attack, {}, {}, timeline, "", status);
}