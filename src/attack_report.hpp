#pragma once

#include <ctime>
#include <map>
#include <string>
#include <vector>

#include <boost/circular_buffer.hpp>

#include "attack_details.hpp"
#include "fastnetmon_pcap_format.hpp"
#include "fastnetmon_types.hpp"

// ---------------------------------------------------------------------------
// Post-mortem attack analysis: top talkers, attack classification,
// timeline events, PCAP fingerprint dump and JSON attack report.
// ---------------------------------------------------------------------------

// Classification of the attack vector based on protocol distribution,
// ports and TCP flags in the captured packet sample.
enum class attack_classification_t : uint32_t {
    UNKNOWN = 0,
    SYN_FLOOD = 1,
    UDP_FLOOD = 2,
    DNS_AMPLIFICATION = 3,
    NTP_AMPLIFICATION = 4,
    ICMP_FLOOD = 5,
    ACK_FLOOD = 6,
    UDP_FRAGMENT_FLOOD = 7,
    MIXED = 8,
    SSDP_AMPLIFICATION = 9,
    SNMP_AMPLIFICATION = 10,
    CHARGEN_AMPLIFICATION = 11,
};

// Single top talker entry: source IP (or destination IP for outgoing attacks)
// with aggregated packet and byte counts from the captured sample.
struct top_talker_entry_t {
    std::string ip;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

// Single timeline event in the attack lifecycle
struct timeline_event_t {
    std::string event_type;
    time_t timestamp = 0;
    std::string details;
};

// Result of attack classification with supporting statistics
struct attack_classification_result_t {
    attack_classification_t type = attack_classification_t::UNKNOWN;

    // Human readable description with key statistics
    std::string description;

    // Protocol distribution ratios (0.0 - 1.0) from the packet sample
    double tcp_ratio = 0.0;
    double udp_ratio = 0.0;
    double icmp_ratio = 0.0;

    // Number of unique source IPs in the sample
    uint64_t unique_src_ips = 0;

    // Number of unique destination ports in the sample
    uint64_t unique_dst_ports = 0;

    // Average packet size in bytes
    double avg_packet_size = 0.0;
};

// Configurable parameters for attack report generation
struct attack_report_config_t {
    // Write raw attack packets to PCAP file (feature 1)
    bool pcap_dump = true;

    // Linktype for the PCAP file: 1 = ETHERNET, 113 = LINUX_SLL
    uint32_t pcap_dump_linktype = FASTNETMON_PCAP_LINKTYPE_ETHERNET;

    // Write JSON attack report with timeline, top talkers, classification (features 2,3,4,5)
    bool attack_report = true;

    // Maximum number of top talker entries in the report
    unsigned int top_talkers_max_entries = 20;
};

extern attack_report_config_t global_attack_report_config;

// Read attack report config from the global configuration_map
void read_attack_report_config();

// Write raw packets from circular buffer to PCAP file. Returns true on success.
bool write_pcap_dump(const std::string& file_path,
                     const boost::circular_buffer<fixed_size_packet_storage_t>& raw_packets_buffer,
                     uint32_t linktype);

// Aggregate top talkers from the parsed packet sample. For incoming attacks
// talkers are source IPs, for outgoing attacks they are destination IPs.
std::vector<top_talker_entry_t> aggregate_top_talkers(
    const boost::circular_buffer<simple_packet_t>& simple_packets_buffer,
    direction_t attack_direction,
    unsigned int max_entries);

// Classify attack type from traffic counters and the packet sample
attack_classification_result_t classify_attack(const subnet_counter_t& traffic_counters,
                                               direction_t attack_direction,
                                               const boost::circular_buffer<simple_packet_t>& simple_packets_buffer);

// Get report file path for attack: <attack_details_folder>/<ip>_<ban_ts>_<uuid>.json
std::string get_attack_report_file_path(const std::string& client_ip_as_string, const attack_details_t& current_attack);

// Get PCAP dump file path for attack: <attack_details_folder>/<ip>_<ban_ts>_<uuid>.pcap
std::string get_attack_pcap_file_path(const std::string& client_ip_as_string, const attack_details_t& current_attack);

// Write attack report JSON file. If the file already exists (e.g. unban event
// after ban), it will be updated with new events.
bool write_attack_report(const std::string& client_ip_as_string,
                         const attack_details_t& current_attack,
                         const std::vector<top_talker_entry_t>& top_talkers,
                         const attack_classification_result_t& classification,
                         const std::vector<timeline_event_t>& timeline,
                         const std::string& pcap_file_path,
                         const std::string& status);

// Add a single timeline event to an existing report (creates report if missing)
bool append_timeline_event_to_report(const std::string& client_ip_as_string,
                                     const attack_details_t& current_attack,
                                     const std::string& event_type,
                                     const std::string& details,
                                     const std::string& status = "");
