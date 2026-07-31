# Per-IP Limits for Customers: Architecture Analysis

## Overview

FastNetMon already has most of the plumbing needed to enforce per-IP traffic limits on a per-customer basis. This document reviews the existing architecture and identifies what is already in place versus what would need to be added.

## Current Architecture

### 1. Traffic Counting (Per-IP)

Every IP address in the monitored networks gets per-IP counters:

- **IPv4**: `abstract_subnet_counters_t<uint32_t, subnet_counter_t> ipv4_host_counters` — keyed by `/32` IP address as `uint32_t`
- **IPv6**: `abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t, subnet_counter_t> ipv6_host_counters` — keyed by `/128` subnet

Each `subnet_counter_t` holds **in/out packets, bytes, flows** per protocol (total, tcp, udp, icmp, fragmented, tcp_syn, dropped). These are updated from every packet/flow. Speed is calculated via exponential moving average in `recalculate_speed()`.

### 2. IP-to-Customer Mapping

**Patricia trees** map any IP to the customer subnet it belongs to:

- `lookup_tree_ipv4` — maps IPv4 -> `subnet_cidr_mask_t`
- `lookup_tree_ipv6` — maps IPv6 addresses

The lookup function `lookup_ip_in_integer_form_inpatricia_and_return_subnet_if_found()` returns the containing customer subnet.

### 3. Customer Subnet to Host Group Mapping

```cpp
typedef std::map<subnet_cidr_mask_t, std::string> subnet_to_host_group_map_t;
```

Maps a customer subnet (e.g. `203.0.113.0/24`) to a host group name (e.g. `"premium"`). Configured via:

```
hostgroup = premium:203.0.113.0/24,203.0.114.0/24
```

### 4. Host Group to Ban Thresholds

```cpp
typedef std::map<std::string, ban_settings_t> host_group_ban_settings_map_t;
```

Each host group has its own `ban_settings_t` with per-threshold enables and values:

| Field | Type | Description |
|---|---|---|
| `enable_ban` | bool | Master switch for ban actions |
| `enable_ban_ipv6` | bool | Separate IPv6 switch |
| `ban_threshold_mbps` | unsigned int | Total bandwidth (Mbps) |
| `ban_threshold_pps` | unsigned int | Total packets per second |
| `ban_threshold_flows` | unsigned int | Flows per second |
| `ban_threshold_tcp_mbps/pps` | unsigned int | Per-protocol thresholds |
| `ban_threshold_udp_mbps/pps` | unsigned int | |
| `ban_threshold_icmp_mbps/pps` | unsigned int | |

### 5. Per-IP Detection Flow

The function `speed_calculation_callback_local_ipv4()` runs as a callback **per IP** during speed recalculation:

1. Gets the IP's average speed element
2. Looks up the customer subnet via patricia tree
3. Resolves the host group from the subnet
4. Loads `ban_settings_t` for that host group
5. Calls `we_should_ban_this_entity(speed_element, ban_settings, ...)` which checks if the IP exceeds the configured thresholds
6. If yes, triggers the ban pipeline

## What Already Works

**Per-IP limits per customer are already enforceable** for IPv4 via host groups. Example config:

```
# In fastnetmon.conf:
hostgroup = bronze:10.0.0.0/24
bronze_enable_ban = on
bronze_ban_for_bandwidth = on
bronze_ban_for_pps = on
bronze_threshold_mbps = 100
bronze_threshold_pps = 50000

hostgroup = silver:10.0.1.0/24
silver_enable_ban = on
silver_ban_for_bandwidth = on
silver_ban_for_pps = on
silver_threshold_mbps = 500
silver_threshold_pps = 200000

hostgroup = gold:10.0.2.0/24
gold_enable_ban = on
gold_ban_for_bandwidth = on
gold_ban_for_pps = on
gold_threshold_mbps = 1000
gold_threshold_pps = 500000
```

This gives each customer tier different per-IP limits. An IP in `10.0.0.5` (bronze) gets banned at 100 Mbps, while `10.0.2.10` (gold) gets banned at 1000 Mbps.

## Limitations / Gaps

### IPv6 Host Groups

**Not supported.** The `speed_calculation_callback_local_ipv6()` function uses `global_ban_settings` only, with the comment `"We support only global group"`. There is a TODO: `"Also, we should find IPv6 network for attack here"`. The patricia tree for IPv6 (`lookup_tree_ipv6`) exists, but the host group lookup and per-customer-subnet IPv6 ban settings are not wired in.

**Impact**: IPv6 customers cannot have per-customer differentiated limits. All IPv6 traffic uses the same `global_ban_settings` thresholds.

### Host Group Subnet Parsing is IPv4-Only

In `parse_hostgroups()` (`fastnetmon.cpp:542`), subnet parsing uses `convert_subnet_from_string_to_binary_with_cidr_format_safe()` which parses IPv4 CIDR notation only. IPv6 subnets (e.g. `2001:db8::/32`) cannot be added to host groups.

### Ban is the Only Action

When a per-IP limit is exceeded, the only enforcement action is **blackhole ban** (RTBH via BGP or ExaBGP). There is no:
- **Soft limit / warning** — a threshold that triggers a notification but not a ban
- **Rate limiting** — apply a flowspec rate-limit action instead of full blackhole (note: the flowspec action module does support `rate-limit` actions, but it is not wired into the per-IP threshold enforcement path)
- **Traffic shaping / policing** — no data-plane rate limiting

### Ban Thresholds are Binary

The `ban_settings_t` thresholds are "exceed -> ban" with no hysteresis:
- No "alert at X, ban at Y" two-tier model
- No time-windowed violation counting
- The `ban_time` parameter controls duration, but there is no "repeat offender" escalation

### Per-IP Not Per-Subnet Limits

The detection is per-IP (each `/32` or `/128`). If a customer has a `/24` (256 IPs), the limits apply individually to each IP. There is no **aggregate** limit across the customer's subnet (e.g. "total of 1 Gbps across all 256 IPs"). This is a design choice — the current model is attack detection per IP, not capacity management.

## What Would Be Needed for Full Customer Limits

### Minimal effort (existing infrastructure)

| Feature | Effort | Notes |
|---|---|---|
| Enable IPv6 customer limits | ~1-2 days | Wire `lookup_tree_ipv6` + `subnet_to_host_groups` (or a new IPv6 map) into `speed_calculation_callback_local_ipv6()` |
| Soft limit / alert-only threshold | ~1 day | Add a new field to `ban_settings_t` (e.g. `alert_threshold_mbps`) that triggers a notification without banning |

### Moderate effort

| Feature | Effort | Notes |
|---|---|---|
| Flowspec rate-limit enforcement | ~3-5 days | Wire the existing flowspec rate-limit action into the per-IP threshold breach path so that instead of /32 blackhole, a rate-limited flowspec rule is installed |
| Per-subnet aggregate limit | ~3-5 days | Needs a new counter structure summing per-IP speeds within a subnet, plus an aggregate threshold check in `recalculate_speed()` |

### Major effort

| Feature | Effort | Notes |
|---|---|---|
| Two-tier (alert+ban) thresholds | ~1 week | New threshold fields, hysteresis logic, duplicate detection prevention |
| Graceful degradation / progressive action | ~2 weeks | Escalation: alert -> rate-limit -> blackhole, with configurable time windows |
| Per-IP bandwidth cap enforcement (not just attack detection) | ~2 weeks | This is a fundamentally different model — continuous enforcement vs threshold-based reaction. Would need a separate subsystem |

## Conclusion

**Yes, per-IP limits per customer are possible** with the current architecture. The host group system already provides per-customer threshold differentiation. The main gaps are:

1. **IPv6 customer groups** — not implemented, but the patricia tree infrastructure exists
2. **Enforcement options beyond blackhole** — flowspec rate-limit exists in the codebase but is not wired into the per-IP threshold path
3. **Soft/pre-emptive limits** — no alert-only or graduated response mechanism

The quickest path to a working per-IP customer limit system is to configure IPv4 host groups with different thresholds per customer subnet. For IPv6, the host group support would need to be added.