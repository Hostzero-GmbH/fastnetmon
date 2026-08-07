# Prometheus Integration

## Overview

FastNetMon exposes a Prometheus metrics endpoint at `/metrics` on the configured host and port.

## Configuration

In `fastnetmon.conf`:

```
prometheus = on
prometheus_port = 9209
prometheus_host = 127.0.0.1
```

## Metrics

### System Counters

Standard application statistics prefixed with `fastnetmon_`:

| Metric | Type | Description |
|---|---|---|
| `fastnetmon_total_simple_packets_processed` | counter | Total packets processed |
| `fastnetmon_total_ipv4_packets` | counter | IPv4 packets processed |
| `fastnetmon_total_ipv6_packets` | counter | IPv6 packets processed |
| `fastnetmon_total_unparsed_packets` | counter | Unparsed packets |
| `fastnetmon_total_unparsed_packets_speed` | gauge | Current unparsed packet rate |
| `fastnetmon_speed_recalculation_time_seconds` | gauge | Speed calculation duration |
| `fastnetmon_total_number_of_hosts` | gauge | Hosts in monitored networks |
| `fastnetmon_influxdb_writes_total` | counter | InfluxDB write count |
| `fastnetmon_influxdb_writes_failed` | counter | Failed InfluxDB writes |

Additional sFlow, NetFlow, and AF_PACKET counters appear when those plugins are enabled.

### Total Traffic

| Metric | Type | Labels | Description |
|---|---|---|---|
| `fastnetmon_total_traffic_packets` | gauge | `traffic_direction`, `protocol_version` | Total traffic in packets/sec |
| `fastnetmon_total_traffic_bits` | gauge | `traffic_direction`, `protocol_version` | Total traffic in bits/sec |
| `fastnetmon_total_traffic_flows` | gauge | `traffic_direction`, `protocol_version` | Total traffic in flows/sec |

`traffic_direction`: `incoming`, `outgoing`, `internal`, `other`
`protocol_version`: `ipv4`, `ipv6`

### Per-IP Host Traffic

| Metric | Type | Labels | Description |
|---|---|---|---|
| `fastnetmon_host_traffic_bits` | gauge | `ip`, `traffic_direction`, `protocol_version` | Per-IP traffic in bits/sec |
| `fastnetmon_host_traffic_packets` | gauge | `ip`, `traffic_direction`, `protocol_version` | Per-IP traffic in packets/sec |
| `fastnetmon_host_traffic_flows` | gauge | `ip`, `traffic_direction`, `protocol_version` | Per-IP traffic in flows/sec |

Only IPs with non-zero traffic are reported. `traffic_direction` is `incoming` or `outgoing`.

### Banned Routes

| Metric | Type | Labels | Description |
|---|---|---|---|
| `fastnetmon_banned_routes` | gauge | `ip`, `protocol_version`, `host_group`, `attack_uuid`, `mitigation_type` | Currently banned routes (value=1). `mitigation_type` is `rtbh`, `flowspec`, or `unknown` |
| `fastnetmon_banned_routes_ban_timestamp_seconds` | gauge | `ip`, `protocol_version`, `mitigation_type` | Unix timestamp when the route was banned |
| `fastnetmon_banned_routes_total` | gauge | `protocol_version` | Total number of currently banned routes |

## Prometheus Scrape Config Example

```yaml
scrape_configs:
  - job_name: 'fastnetmon'
    static_configs:
      - targets: ['127.0.0.1:9209']
```

## Example PromQL Queries

```promql
# Total incoming traffic (IPv4)
fastnetmon_total_traffic_bits{protocol_version="ipv4", traffic_direction="incoming"}

# Top 10 IPs by incoming traffic
topk(10, fastnetmon_host_traffic_bits{traffic_direction="incoming"})

# Count of currently banned IPv4 routes
fastnetmon_banned_routes_total{protocol_version="ipv4"}

# Banned routes with their host group
fastnetmon_banned_routes{protocol_version="ipv4"}

# Banned routes where the ban is older than 10 minutes
fastnetmon_banned_routes_ban_timestamp_seconds < (time() - 600)

# Alert when more than 10 routes are banned
  fastnetmon_banned_routes_total{protocol_version="ipv4"}
> 10
```