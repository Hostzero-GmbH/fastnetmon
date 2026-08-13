#pragma once

#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "attack_details.hpp"
#include "fastnetmon_types.hpp"

// Post-unban verification: after an IP is unbanned, we keep observing it for a
// configurable interval. If the attack resumes above the thresholds, we re-ban
// it immediately (fast path, no new packet capture). If the observation
// interval expires without re-detection, the attack is confirmed finished.
struct unban_verification_entry_t {
    // IP address as string (used as key)
    std::string ip_as_string;

    // Whether this is an IPv6 entry
    bool ipv6 = false;

    // Attack details at unban time (for report updates and re-ban)
    attack_details_t attack_details;

    // Attack detection thresholds used for re-ban check
    uint64_t threshold_pps = 0;
    uint64_t threshold_mbps = 0;
    uint64_t threshold_flows = 0;

    // When the IP was unbanned (epoch seconds)
    std::time_t unban_time = 0;

    // Observation interval in seconds
    unsigned int observation_interval = 300;
};

// Thread-safe manager for post-unban verification entries
class unban_verification_manager_t {
    public:
    unban_verification_manager_t() = default;

    // Add an IP to verification watch list (called on unban)
    void add(const std::string& ip_as_string,
             bool ipv6,
             const attack_details_t& attack_details,
             uint64_t threshold_pps,
             uint64_t threshold_mbps,
             uint64_t threshold_flows,
             unsigned int observation_interval);

    // Remove an IP from verification watch list
    void remove(const std::string& ip_as_string);

    // Get all entries under verification
    void get_entries(std::vector<unban_verification_entry_t>& entries) const;

    // Check if an IP is under verification
    bool is_under_verification(const std::string& ip_as_string) const;

    // Number of entries under verification
    size_t size() const;

    private:
    std::map<std::string, unban_verification_entry_t> entries_;
    mutable std::mutex mutex_;
};

// Global verification manager instance
extern unban_verification_manager_t global_unban_verification_manager;

// Configurable post-unban verification parameters
struct unban_verification_config_t {
    // Master enable
    bool enabled = false;

    // Observation interval in seconds (default 5 minutes)
    unsigned int observation_interval = 300;

    // Re-ban immediately if attack resumes during verification
    bool reban = true;

    // How often the checker thread samples traffic (seconds)
    unsigned int check_interval = 10;
};

extern unban_verification_config_t global_unban_verification_config;

// Read post-unban verification config from the global configuration_map
void read_unban_verification_config();
