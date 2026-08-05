#include "escalation_manager.hpp"

#include <cmath>
#include <cstring>
#include <sstream>

#include "all_logcpp_libraries.hpp"
#include "fast_library.hpp"

extern log4cpp::Category& logger;

// Global instances
escalation_manager_t global_escalation_manager;
escalation_config_t global_escalation_config;

// ---------------------------------------------------------------------------
// escalation_manager_t implementation
// ---------------------------------------------------------------------------

void escalation_manager_t::register_flowspec(const std::string& ip_as_string,
                                             bool ipv6,
                                             const attack_details_t& attack_details,
                                             uint64_t threshold_pps,
                                             uint64_t threshold_mbps,
                                             uint64_t threshold_flows) {
    std::lock_guard<std::mutex> lock(mutex_);

    escalation_entry_t entry;
    entry.stage = escalation_stage_t::FLOWSPEC;
    entry.flowspec_deploy_time = std::time(nullptr);
    entry.ip_as_string = ip_as_string;
    entry.ipv6 = ipv6;
    entry.attack_details = attack_details;
    entry.threshold_pps = threshold_pps;
    entry.threshold_mbps = threshold_mbps;
    entry.threshold_flows = threshold_flows;

    entries_[ip_as_string] = entry;

    logger << log4cpp::Priority::INFO << "Escalation: registered FlowSpec for " << ip_as_string;
}

void escalation_manager_t::mark_rtbh(const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(ip_as_string);
    if (it != entries_.end()) {
        it->second.stage = escalation_stage_t::RTBH;
        logger << log4cpp::Priority::INFO << "Escalation: marked " << ip_as_string << " as RTBH";
    }
}

void escalation_manager_t::remove(const std::string& ip_as_string) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(ip_as_string);
    if (it != entries_.end()) {
        logger << log4cpp::Priority::INFO << "Escalation: removed tracking for " << ip_as_string;
        entries_.erase(it);
    }
}

escalation_stage_t escalation_manager_t::get_stage(const std::string& ip_as_string) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(ip_as_string);
    if (it == entries_.end()) {
        return escalation_stage_t::NONE;
    }
    return it->second.stage;
}

void escalation_manager_t::get_flowspec_entries(std::vector<escalation_entry_t>& entries) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& kv : entries_) {
        if (kv.second.stage == escalation_stage_t::FLOWSPEC) {
            entries.push_back(kv.second);
        }
    }
}

void escalation_manager_t::get_rtbh_entries(std::vector<escalation_entry_t>& entries) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& kv : entries_) {
        if (kv.second.stage == escalation_stage_t::RTBH) {
            entries.push_back(kv.second);
        }
    }
}

bool escalation_manager_t::is_tracked(const std::string& ip_as_string) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.find(ip_as_string) != entries_.end();
}

size_t escalation_manager_t::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

void read_escalation_config() {
    extern std::map<std::string, std::string> configuration_map;

    if (configuration_map.count("escalation") != 0) {
        global_escalation_config.enabled = configuration_map["escalation"] == "on";
    }

    if (configuration_map.count("escalation_check_interval") != 0) {
        int val = convert_string_to_integer(configuration_map["escalation_check_interval"]);
        if (val > 0) {
            global_escalation_config.check_interval = static_cast<unsigned int>(val);
        }
    }

    if (configuration_map.count("escalation_rtbh_threshold_ratio") != 0) {
        int val = convert_string_to_integer(configuration_map["escalation_rtbh_threshold_ratio"]);
        if (val > 0 && val <= 100) {
            global_escalation_config.rtbh_threshold_ratio = static_cast<unsigned int>(val);
        }
    }

    if (global_escalation_config.enabled) {
        logger << log4cpp::Priority::INFO << "Escalation enabled: check_interval="
               << global_escalation_config.check_interval << "s, rtbh_threshold_ratio="
               << global_escalation_config.rtbh_threshold_ratio << "%";
    }
}