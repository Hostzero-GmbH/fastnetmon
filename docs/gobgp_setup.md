# GoBGP Setup for FastNetMon Flowspec Mitigation

This guide replaces FRR + notify-script blackholing with GoBGP flowspec via gRPC.

## Architecture

```
FastNetMon ──gRPC:50051──► GoBGP ──BGP flowspec──► Upstream Router
                              │
                          gobgpd daemon
                       /etc/gobgp/gobgpd.conf
```

## 1. Install GoBGP

On **netmon**:

```bash
# Download latest amd64 binary
wget -O /tmp/gobgpd https://github.com/osrg/gobgp/releases/latest/download/gobgpd-linux-amd64
wget -O /tmp/gobgp https://github.com/osrg/gobgp/releases/latest/download/gobgp-linux-amd64
chmod +x /tmp/gobgpd /tmp/gobgp
sudo mv /tmp/gobgpd /usr/local/sbin/gobgpd
sudo mv /tmp/gobgp /usr/local/bin/gobgp
```

## 2. Configure GoBGP

Create `/etc/gobgp/gobgpd.conf`:

```toml
[global.config]
  as = <YOUR_ASN>              # ← FILL IN: netmon's ASN
  router-id = "<LOOPBACK_IP>"  # ← FILL IN: e.g. 10.0.0.1
  port = -1                    # no inbound BGP, only outgoing

# ============================================================
# gRPC API — fastnetmon connects here
# ============================================================
[grpc.config]
  address = "localhost:50051"

# ============================================================
# BGP peer — upstream router
# ============================================================
[[neighbors]]
  [neighbors.config]
    peer-as = <UPSTREAM_ASN>            # ← FILL IN
    neighbor-address = "<UPSTREAM_IP>"  # ← FILL IN
    local-as = <YOUR_ASN>
    auth-password = ""                  # set if MD5/TCP-AO is used

  [neighbors.transport.config]
    local-address = "<LOOPBACK_IP>"     # source IP for BGP session

  # Advertise IPv4 flowspec SAFI (RFC 5575)
  [neighbors.afi-safis]
    [[neighbors.afi-safis.config]]
      afi-safi-name = "ipv4-flowspec"

# ============================================================
# Flowspec policy — set the blackhole community
# ============================================================
[[defined-sets.community-set]]
  name = "blackhole-comm"
  [defined-sets.community-set.list]
    communities = ["65535:666"]

# Mark all flowspec routes from gRPC with the blackhole community
[[policy-definitions]]
  name = "fnm-flowspec"
  [[policy-definitions.statements]]
    name = "set-community"
    [policy-definitions.statements.actions.community]
      action = "ADD"
      community-set-ref = "blackhole-comm"

# Apply policy to the upstream peer
[[neighbors.apply-policy]]
  neighbor-address = "<UPSTREAM_IP>"  # ← FILL IN: same as above
  [neighbors.apply-policy.config]
    export-policy = "fnm-flowspec"
```

Replace `<YOUR_ASN>`, `<LOOPBACK_IP>`, `<UPSTREAM_ASN>`, `<UPSTREAM_IP>` with your actual values.

## 3. Start GoBGP

### Test run

```bash
sudo gobgpd -f /etc/gobgp/gobgpd.conf
```

### Systemd service

Create `/etc/systemd/system/gobgpd.service`:

```ini
[Unit]
Description=GoBGP BGP daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/gobgpd -f /etc/gobgp/gobgpd.conf
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gobgpd
```

## 4. Configure FastNetMon

In `fastnetmon.conf`, **remove the notify script** and **enable GoBGP**:

```ini
# ── Disable old notify script ──
# notify_script_path = /path/to/your/old/script.sh   ← comment or remove

# ── Enable GoBGP ──
gobgp = on
gobgp_next_hop = <LOOPBACK_IP>  # ← same as router-id above

# ── Flowspec action per host group ──
# Default: blackhole (/32 unicast) — works with ExaBGP too
# For flowspec rate-limit:
my_hosts_ban_action = flow_spec_discard
my_hosts_flow_spec_rate_limit = 0

# Full list of actions:
#   blackhole              — /32 unicast blackhole (default)
#   flow_spec_discard      — flowspec discard rule
#   flow_spec_rate_limit   — flowspec rate-limit (set flow_spec_rate_limit = <bytes/sec>)
#   flow_spec_redirect     — flowspec redirect (set redirect target in advanced config)
```

## 5. Verify

```bash
# Check BGP session state
sudo gobgp neighbor

# Check announced flowspec rules
sudo gobgp global rib -a ipv4-flowspec

# FastNetMon should log:
#   "Call GoBGP flowspec for ban client started: x.x.x.x"
#   "Flowspec ban for x.x.x.x"

# Check netmon's BGP table
sudo gobgp global rib
```

## 6. Troubleshooting

| Issue | Check |
|---|---|
| gRPC connection refused | `netstat -tlnp \| grep 50051` — gobgpd must be running |
| BGP session not established | `sudo gobgp neighbor`, check IP/ASN/auth |
| Flowspec rules not announced | `sudo gobgp global rib -a ipv4-flowspec` |
| Upstream not installing flowspec | Check upstream's flowspec policy; community `65535:666` must be meaningful to them |
| FastNetMon still calling old notify script | Comment out `notify_script_path` in fastnetmon.conf |