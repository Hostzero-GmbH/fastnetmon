#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "fastnetmon_networks.hpp"
#include "fastnetmon_types.hpp"
#include "attack_details.hpp"

// Escalation stages for the FlowSpec-first, RTBH-fallback model
enum class escalation_stage_t : uint32_t {
    // No active mitigation tracked for this IP
    NONE = 0,
    // FlowSpec deployed, monitoring effectiveness
    FLOWSPEC = 1,
    // Escalated to RTBH because FlowSpec was insufficient
    RTBH = 2,
};

// Per-IP escalation state stored in the manager
struct escalation_entry_t {
    escalation_stage_t stage = escalation_stage_t::NONE;

    // Timestamp when we deployed FlowSpec (epoch seconds)
    std::time_t flowspec_deploy_time = 0;

    // The target IP address (string form for logging)
    std::string ip_as_string;

    // Whether this is an IPv6 entry
    bool ipv6 = false;

    // Copy of attack details at time of deployment
    attack_details_t attack_details;

    // The thresholds that triggered this attack (from ban_settings)
    uint64_t threshold_pps = 0;
    uint64_t threshold_mbps = 0;
    uint64_t threshold_flows = 0;
};

// Manages escalation state for all mitigated IPs.
// Thread-safe: all public methods lock internally.
class escalation_manager_t {
    public:
    escalation_manager_t() = default;

    // Register an IP that has just had FlowSpec deployed.
    // The escalation checker will monitor this IP and escalate to RTBH if needed.
    void register_flowspec(const std::string& ip_as_string,
                           bool ipv6,
                           const attack_details_t& attack_details,
                           uint64_t threshold_pps,
                           uint64_t threshold_mbps,
                           uint64_t threshold_flows);

    // Mark an IP as escalated to RTBH (called by the escalation checker)
    void mark_rtbh(const std::string& ip_as_string);

    // Step down from RTBH back to FlowSpec stage (de-escalation)
    void step_down_to_flowspec(const std::string& ip_as_string);

    // Remove an IP from escalation tracking entirely (unban/cleanup)
    void remove(const std::string& ip_as_string);

    // Get current stage for an IP
    escalation_stage_t get_stage(const std::string& ip_as_string) const;

    // Get all entries currently at the FlowSpec stage (for the checker thread)
    void get_flowspec_entries(std::vector<escalation_entry_t>& entries) const;

    // Get all entries currently at the RTBH stage
    void get_rtbh_entries(std::vector<escalation_entry_t>& entries) const;

    // Check if an IP is tracked at any stage
    bool is_tracked(const std::string& ip_as_string) const;

    // Number of tracked entries
    size_t size() const;

    private:
    std::unordered_map<std::string, escalation_entry_t> entries_;
    mutable std::mutex mutex_;
};

// Global escalation manager instance
extern escalation_manager_t global_escalation_manager;

// Configurable escalation parameters
struct escalation_config_t {
    // Master enable: off by default for backward compatibility
    bool enabled = false;

    // Seconds to wait after FlowSpec deployment before checking effectiveness
    unsigned int check_interval = 10;

    // Percentage of original attack threshold that, if still exceeded, triggers
    // escalation to RTBH. e.g. 80 means "if attack still exceeds 80% of the
    // threshold that triggered it, escalate to RTBH".
    unsigned int rtbh_threshold_ratio = 80;

    // BGP community for the escalation RTBH route (RFC 7999 default)
    std::string rtbh_community = "65535:666";
};

extern escalation_config_t global_escalation_config;

// Read escalation config from the global configuration_map
void read_escalation_config();