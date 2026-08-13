#include "unban_verification_manager.hpp"

#include <map>
#include <string>

#include "all_logcpp_libraries.hpp"
#include "fast_library.hpp"

extern log4cpp::Category& logger;

extern std::map<std::string, std::string> configuration_map;

// Global instances
unban_verification_manager_t global_unban_verification_manager;
unban_verification_config_t global_unban_verification_config;

// ---------------------------------------------------------------------------
// unban_verification_manager_t implementation
// ---------------------------------------------------------------------------

void unban_verification_manager_t::add(const std::string& ip_as_string,
                                       bool ipv6,
                                       const attack_details_t& attack_details,
                                       uint64_t threshold_pps,
                                       uint64_t threshold_mbps,
                                       uint64_t threshold_flows,
                                       unsigned int observation_interval) {
    std::lock_guard<std::mutex> lock(mutex_);

    unban_verification_entry_t entry;
    entry.ip_as_string = ip_as_string;
    entry.ipv6 = ipv6;
    entry.attack_details = attack_details;
    entry.threshold_pps = threshold_pps;
    entry.threshold_mbps = threshold_mbps;
    entry.threshold_flows = threshold_flows;
    entry.unban_time = std::time(nullptr);
    entry.observation_interval = observation_interval;

    entries_[ip_as_string] = entry;

    logger << log4cpp::Priority::INFO << "Post-unban verification: added " << ip_as_string
           << " for " << observation_interval << " seconds";
}

void unban_verification_manager_t::remove(const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(ip_as_string);
    if (it != entries_.end()) {
        logger << log4cpp::Priority::INFO << "Post-unban verification: removed " << ip_as_string;
        entries_.erase(it);
    }
}

void unban_verification_manager_t::get_entries(std::vector<unban_verification_entry_t>& entries) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& kv : entries_) {
        entries.push_back(kv.second);
    }
}

bool unban_verification_manager_t::is_under_verification(const std::string& ip_as_string) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.find(ip_as_string) != entries_.end();
}

size_t unban_verification_manager_t::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

void read_unban_verification_config() {
    if (configuration_map.count("post_unban_verification") != 0) {
        global_unban_verification_config.enabled = configuration_map["post_unban_verification"] == "on";
    }

    if (configuration_map.count("post_unban_verification_interval") != 0) {
        int val = convert_string_to_integer(configuration_map["post_unban_verification_interval"]);
        if (val > 0) {
            global_unban_verification_config.observation_interval = static_cast<unsigned int>(val);
        }
    }

    if (configuration_map.count("post_unban_verification_reban") != 0) {
        global_unban_verification_config.reban = configuration_map["post_unban_verification_reban"] == "on";
    }

    if (configuration_map.count("post_unban_verification_check_interval") != 0) {
        int val = convert_string_to_integer(configuration_map["post_unban_verification_check_interval"]);
        if (val > 0) {
            global_unban_verification_config.check_interval = static_cast<unsigned int>(val);
        }
    }

    if (global_unban_verification_config.enabled) {
        logger << log4cpp::Priority::INFO << "Post-unban verification enabled: observation_interval="
               << global_unban_verification_config.observation_interval << "s, reban="
               << (global_unban_verification_config.reban ? "on" : "off") << ", check_interval="
               << global_unban_verification_config.check_interval << "s";
    }
}