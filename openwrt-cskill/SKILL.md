---
name: openwrt-cskill
description: "Ansible collection harley.openwrt assistant. Use when the user needs to configure OpenWRT routers or Linux gateways using Ansible, create playbooks with harley.openwrt roles (base, network, firewall, dhcp_dns, ipsec, ipsec_gateway, acme, ddns, ddns_gateway, webui), manage UCI configuration, set up StrongSwan VPN, ACME certificates, DHCP/DNS, dynamic DNS, firewall zones, WiFi, or troubleshoot OpenWRT Ansible deployments."
user-invocable: true
argument-hint: "[role, task, or question]"
---

# Ansible Collection harley.openwrt - Claude Skill

This skill provides Claude with comprehensive knowledge of the `harley.openwrt` Ansible collection to assist users with configuring OpenWRT routers and Linux/Ubuntu gateways.

## Collection Location

- **Source repository**: `~/src/ansible-collection-openwrt/`
- **Namespace**: `harley.openwrt`
- **Version**: 0.1.0
- **License**: MIT
- **GitHub**: https://github.com/harley-systems/ansible-collection-openwrt

## When to Use This Skill

Activate when the user:

- Asks about configuring OpenWRT routers with Ansible
- Wants to create or modify playbooks using `harley.openwrt` roles
- Needs to set up network interfaces (WAN, LAN, WiFi) on OpenWRT
- Configures firewall zones, rules, or forwarding on OpenWRT
- Sets up DHCP/DNS (dnsmasq) static leases, DNS records, or CNAME aliases
- Configures StrongSwan IPsec VPN (on OpenWRT or Linux gateways)
- Needs ACME/Let's Encrypt certificates with DNS-01 challenge
- Sets up dynamic DNS (DDNS) on OpenWRT or Linux
- Configures LuCI web UI with HTTPS
- Uses the `harley.openwrt.uci` module to manage UCI configuration
- Uses the `host_names_to_ip_addresses` filter
- Asks about inventory conventions for this collection
- Needs to troubleshoot Ansible deployments to OpenWRT devices
- Works with this collection's source code (roles, templates, plugins)

## Architecture Overview

```
harley.openwrt Collection
├── OpenWRT Roles (target: OpenWRT routers)
│   ├── base         - Initial setup (Python, SSH, ansible user)
│   ├── network      - WAN/LAN/WiFi configuration
│   ├── firewall     - Zone-based firewall (iptables)
│   ├── dhcp_dns     - dnsmasq DHCP server + DNS
│   ├── ipsec        - StrongSwan VPN (OpenWRT)
│   ├── acme         - Let's Encrypt via acme.sh
│   ├── ddns         - Dynamic DNS (ddns-scripts)
│   └── webui        - LuCI HTTPS (uhttpd)
├── Linux Gateway Roles (target: Ubuntu/Debian)
│   ├── ipsec_gateway  - StrongSwan VPN (systemd)
│   └── ddns_gateway   - DDNS via systemd timers
├── Plugins
│   ├── modules/uci.py              - UCI config management
│   └── filter/hostnames_to_vars.py - Hostname-to-IP filter
└── Playbooks/Includes
    └── inventory_to_dhcp_dns.yml   - Inventory adapter
```

## Requirements

- **OpenWRT**: 21.02+ (tested on 23.05)
- **Ansible**: 2.10+
- **Python 3**: On the control node
- **Target**: OpenWRT router (SSH access) or Ubuntu/Debian gateway

## Installation

### From GitHub

```bash
ansible-galaxy collection install git+https://github.com/harley-systems/ansible-collection-openwrt.git
```

### From source (for development)

```bash
# Install to default collection path
cd ~/src/ansible-collection-openwrt
ansible-galaxy collection build
ansible-galaxy collection install harley-openwrt-*.tar.gz

# Or install to a project-local collections directory
ansible-galaxy collection install ~/src/ansible-collection-openwrt -p ./collections --force
```

### In requirements.yml

```yaml
collections:
  - name: git+https://github.com/harley-systems/ansible-collection-openwrt.git
    type: git
```

## Roles Reference

### base - Initial OpenWRT Setup

Prepares a fresh OpenWRT installation for Ansible management. Installs Python 3, pip, SFTP server, user management tools, and creates a dedicated ansible user.

**Tags**: `base`, `detect_connection`, `update_packages`, `install_python3`, `install_pip3`, `install_sftp`, `install_user_management`, `create_ansible_user`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `base_ansible_user` | `ansible` | Username for Ansible |
| `base_ansible_authorized_key` | (required) | SSH public key |
| `base_ansible_password` | (required) | User password |
| `base_ansible_user_groups` | `adm,ansible,wheel` | User groups |
| `base_ansible_user_shell` | `/bin/ash` | User shell |
| `base_install_python` | `true` | Install Python 3 |
| `base_install_pip` | `true` | Install pip3 |
| `base_install_sftp` | `true` | Install SFTP server |
| `base_install_sudo` | `true` | Install sudo |
| `base_update_packages` | `true` | Run opkg update |

**Example**:
```yaml
- role: base
  vars:
    base_ansible_authorized_key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"
    base_ansible_password: "{{ vault_ansible_password }}"
```

---

### network - WAN/LAN/WiFi Configuration

Configures network interfaces: WAN (DHCP, PPPoE, static), LAN (static IP, bridge), and WiFi radios.

**Tags**: `network`, `network_wan`, `network_lan`, `network_wifi`

**WAN Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `network_wan_enabled` | `true` | Enable WAN configuration |
| `network_wan_proto` | `dhcp` | Protocol: `dhcp`, `pppoe`, `static` |
| `network_wan_ifname` | `wan` | WAN interface name |
| `network_wan_device` | `eth1.2` | WAN device |
| `network_wan_pppoe_username` | - | PPPoE username |
| `network_wan_pppoe_password` | - | PPPoE password |
| `network_wan_ipaddr` | - | Static IP address |
| `network_wan_netmask` | - | Static netmask |
| `network_wan_gateway` | - | Static gateway |
| `network_wan_dns` | - | Static DNS servers |
| `network_wan_ipv6` | `auto` | IPv6 mode: `auto`, `disable` |

**LAN Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `network_lan_enabled` | `true` | Enable LAN configuration |
| `network_lan_ifname` | `lan` | LAN interface name |
| `network_lan_proto` | `static` | Protocol (usually static) |
| `network_lan_ipaddr` | `192.168.1.1` | LAN IP address |
| `network_lan_netmask` | `255.255.255.0` | LAN netmask |

**WiFi Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `network_wifi_enabled` | `false` | Enable WiFi configuration |
| `network_wifi_radios` | `[]` | List of radio configurations |

**WiFi radio structure**:
```yaml
network_wifi_radios:
  - radio: radio0           # Radio device name
    country: US             # Country code
    channel: auto           # Channel number or 'auto'
    htmode: VHT80           # HT20, VHT40, VHT80, etc.
    txpower: 20             # Transmit power (dBm)
    ssid: MyNetwork         # Network name
    encryption: sae-mixed   # psk2, sae, sae-mixed, none
    key: "{{ vault_wifi_password }}"
    mode: ap                # ap, sta, adhoc
    disabled: false
    legacy_rates: false
    hidden: false
```

**Example**:
```yaml
- role: network
  vars:
    network_wan_proto: pppoe
    network_wan_pppoe_username: "{{ vault_isp_username }}"
    network_wan_pppoe_password: "{{ vault_isp_password }}"
    network_lan_ipaddr: "10.1.0.1"
    network_lan_netmask: "255.255.255.0"
    network_wifi_enabled: true
    network_wifi_radios:
      - radio: radio0
        country: US
        channel: auto
        htmode: VHT80
        ssid: HomeWiFi
        encryption: sae-mixed
        key: "{{ vault_wifi_password }}"
```

---

### firewall - OpenWRT Firewall Configuration

Manages firewall zones, forwarding rules, and custom rules using UCI/iptables.

**Tags**: `firewall`, `firewall_config`, `firewall_user`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `firewall_syn_flood` | `true` | Enable SYN flood protection |
| `firewall_input` | `ACCEPT` | Default input policy |
| `firewall_output` | `ACCEPT` | Default output policy |
| `firewall_forward` | `REJECT` | Default forward policy |
| `firewall_zones` | (see below) | List of firewall zones |
| `firewall_forwardings` | (see below) | List of zone forwardings |
| `firewall_extra_zones` | `[]` | Additional zones (VPN, guest) |
| `firewall_extra_forwardings` | `[]` | Additional forwardings |
| `firewall_rules` | `[]` | Custom firewall rules |
| `firewall_ipsec_enabled` | `false` | Enable IPsec firewall rules |
| `firewall_include_user` | - | Path to user include script |

**Default zones**:
```yaml
firewall_zones:
  - name: lan
    input: ACCEPT
    output: ACCEPT
    forward: ACCEPT
    network: lan
  - name: wan
    input: REJECT
    output: ACCEPT
    forward: REJECT
    masq: true
    mtu_fix: true
    network: "wan wan6"
```

**Default forwardings**:
```yaml
firewall_forwardings:
  - src: lan
    dest: wan
```

**Custom rule structure**:
```yaml
firewall_rules:
  - name: Allow-SSH-WAN
    src: wan
    dest_port: 22
    proto: tcp
    target: ACCEPT
```

**Example with VPN zone**:
```yaml
- role: firewall
  vars:
    firewall_ipsec_enabled: true
    firewall_extra_zones:
      - name: vpn
        input: ACCEPT
        output: ACCEPT
        forward: ACCEPT
        network: "vti0"
    firewall_extra_forwardings:
      - src: vpn
        dest: lan
      - src: lan
        dest: vpn
```

---

### dhcp_dns - DHCP/DNS Configuration

Configures dnsmasq for DHCP serving and DNS resolution including static leases, DNS A records, and CNAME aliases.

**Tags**: `dhcp_dns`, `dhcp_wan`, `dhcp_lan`, `dns_domain`, `dhcp_options`, `dhcp_static`, `dns_hosts`, `dns_cnames`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `dhcp_dns_domain` | `lan` | Local DNS domain |
| `dhcp_dns_lan_enabled` | `true` | Enable DHCP on LAN |
| `dhcp_dns_lan_start` | `100` | DHCP range start offset |
| `dhcp_dns_lan_limit` | `150` | DHCP range size |
| `dhcp_dns_lan_leasetime` | `12h` | Lease duration |
| `dhcp_dns_wan_enabled` | `false` | Enable DHCP on WAN |
| `dhcp_dns_static_leases` | `[]` | Static DHCP leases |
| `dhcp_dns_hosts` | `[]` | DNS A records |
| `dhcp_dns_cnames` | `[]` | DNS CNAME records |
| `dhcp_dns_lan_options` | `[]` | Extra DHCP options |

**Static lease structure**:
```yaml
dhcp_dns_static_leases:
  - name: server1
    mac: "aa:bb:cc:dd:ee:ff"
    ip: 192.168.1.10
```

**DNS host (A record) structure**:
```yaml
dhcp_dns_hosts:
  - name: server1
    ip: 192.168.1.10
```

**CNAME structure**:
```yaml
dhcp_dns_cnames:
  - alias: git
    target: server1
    name: git_cname    # UCI section name (optional)
```

**Example**:
```yaml
- role: dhcp_dns
  vars:
    dhcp_dns_domain: home.lan
    dhcp_dns_lan_start: 100
    dhcp_dns_lan_limit: 150
    dhcp_dns_static_leases:
      - { name: nas, mac: "aa:bb:cc:dd:ee:01", ip: 192.168.1.10 }
      - { name: printer, mac: "aa:bb:cc:dd:ee:02", ip: 192.168.1.11 }
    dhcp_dns_hosts:
      - { name: nas, ip: 192.168.1.10 }
      - { name: printer, ip: 192.168.1.11 }
    dhcp_dns_cnames:
      - { alias: files, target: nas }
    dhcp_dns_lan_options:
      - "6,192.168.1.1"     # DNS server
      - "15,home.lan"        # Domain name
```

---

### ipsec - StrongSwan IPsec VPN (OpenWRT)

Installs and configures StrongSwan IPsec VPN on OpenWRT routers. Supports road-warrior, site-to-site responder, and site-to-site initiator configurations.

**Tags**: `ipsec`, `ipsec_packages`, `ipsec_dirs`, `ipsec_certs`, `ipsec_updown`, `ipsec_config`, `ipsec_sysctl`, `ipsec_autostart`

**Packages installed**: `strongswan-default`, `strongswan-mod-stroke`, `strongswan-ipsec`, `strongswan-mod-kdf`, `strongswan-mod-openssl`, `iptables-mod-nat-extra`, `vti`, `kmod-ip-vti`, `ip-full`, `bash`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ipsec_charondebug` | `""` | Debug logging settings |
| `ipsec_ike_default` | (strong proposals) | IKE crypto proposals |
| `ipsec_esp_default` | (strong proposals) | ESP crypto proposals |
| `ipsec_dpdaction` | `clear` | Dead peer detection action |
| `ipsec_dpddelay` | `300s` | DPD check interval |
| `ipsec_ca_certs` | `[]` | CA certificates to deploy |
| `ipsec_host_certs` | `[]` | Host certificates to deploy |
| `ipsec_private_keys` | `[]` | Private keys to deploy |
| `ipsec_rsa_key` | - | RSA key file path |
| `ipsec_psk_secrets` | `[]` | Pre-shared key secrets |
| `ipsec_connections` | `[]` | VPN connection definitions |
| `ipsec_autostart` | `false` | Add ipsec start to rc.local |

**Connection structure**:
```yaml
ipsec_connections:
  - name: site-to-cloud
    type: tunnel
    auto: start               # start, add, route
    keyexchange: ikev2
    left: "%defaultroute"
    leftid: "router.example.com"
    leftsubnet: "10.1.0.0/24"
    leftauth: pubkey
    leftcert: router.crt
    right: "cloud.example.com"
    rightid: "cloud.example.com"
    rightsubnet: "10.2.0.0/24"
    rightauth: pubkey
    ike: "aes256-sha256-modp2048!"
    esp: "aes256-sha256!"
    # VTI interface (for route-based VPN)
    leftupdown: "/etc/ipsec.d/ipsec-updown.sh"
    mark: "42"
    vti_if: "vti0"
    vti_local_ip: "10.10.0.1"
    vti_remote_ip: "10.10.0.2"
    vti_local_subnet: "10.1.0.0/24"
    vti_remote_subnet: "10.2.0.0/24"
```

**Certificate deployment**:
```yaml
ipsec_ca_certs:
  - src: files/certs/ca.crt
    dest: ca.crt
ipsec_host_certs:
  - src: files/certs/router.crt
    dest: router.crt
ipsec_private_keys:
  - src: files/certs/router.key
    dest: router.key
```

---

### ipsec_gateway - StrongSwan IPsec VPN (Linux/Ubuntu)

Installs and configures StrongSwan IPsec VPN on Linux/Ubuntu gateways with systemd integration.

**Tags**: `ipsec_gateway`, `ipsec_gateway_packages`, `ipsec_gateway_dirs`, `ipsec_gateway_certs`, `ipsec_gateway_updown`, `ipsec_gateway_config`, `ipsec_gateway_sysctl`, `ipsec_gateway_apparmor`, `ipsec_gateway_services`

**Packages installed**: `strongswan`, `strongswan-pki`, `strongswan-swanctl`, `libcharon-extra-plugins`, `libcharon-extauth-plugins`

**Additional Variables** (shares `ipsec_*` variables with ipsec role):

| Variable | Default | Description |
|----------|---------|-------------|
| `ipsec_gateway_haveged` | `true` | Install haveged for entropy |
| `ipsec_gateway_charon_log_path` | `/var/log/charon.log` | Charon log file |
| `ipsec_gateway_charon_log_default` | `1` | Default log level |
| `ipsec_gateway_apparmor` | `true` | Configure AppArmor |

---

### acme - Let's Encrypt Certificates

Automates Let's Encrypt certificate management on OpenWRT using acme.sh with DNS-01 validation.

**Tags**: `acme`, `acme_packages`, `acme_config`, `acme_credentials`, `acme_service`, `acme_uhttpd`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `acme_email` | (required) | Account email |
| `acme_domain` | (required) | Domain (wildcards supported) |
| `acme_dns_provider` | `dns_cf` | DNS provider for validation |
| `acme_cf_token` | - | Cloudflare API token |
| `acme_cf_zone_id` | - | Cloudflare Zone ID |
| `acme_key_type` | `ec-256` | Key type: `ec-256`, `ec-384`, `rsa-2048`, `rsa-4096` |
| `acme_use_staging` | `false` | Use staging server |
| `acme_configure_uhttpd` | `false` | Auto-configure uhttpd |

**Certificate paths**:
- ECC: `/etc/acme/<domain>_ecc/`
- RSA: `/etc/acme/<domain>/`

**Example**:
```yaml
- role: acme
  vars:
    acme_email: admin@example.com
    acme_domain: "*.home.example.com"
    acme_dns_provider: dns_cf
    acme_cf_token: "{{ vault_cloudflare_token }}"
    acme_cf_zone_id: "{{ vault_cloudflare_zone_id }}"
    acme_configure_uhttpd: true
```

---

### ddns - Dynamic DNS (OpenWRT)

Configures OpenWRT DDNS client using ddns-scripts for automatic domain updates.

**Tags**: `ddns`, `ddns_packages`, `ddns_config`, `ddns_service`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ddns_enabled` | `false` | Enable DDNS |
| `ddns_services` | `[]` | List of DDNS service configs |

**Service structure**:
```yaml
ddns_services:
  - name: myddns
    provider: "cloudflare.com-v4"
    domain: "home.example.com"
    username: "{{ vault_cf_email }}"
    password: "{{ vault_cf_token }}"
    ip_source: web
    ip_url: "http://checkip.amazonaws.com"
    interface: wan
    check_interval: 10
    check_unit: minutes
    force_interval: 72
    force_unit: hours
    retry_interval: 60
    retry_unit: seconds
```

---

### ddns_gateway - Dynamic DNS (Linux/Ubuntu)

Dynamic DNS updates on Linux/Ubuntu using systemd timers and Cloudflare API.

**Tags**: `ddns_gateway`, `ddns_gateway_packages`, `ddns_gateway_config`, `ddns_gateway_services`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `ddns_gateway_enabled` | `false` | Enable DDNS |
| `ddns_gateway_update_interval` | `5min` | Timer interval |
| `ddns_gateway_services` | `[]` | List of DDNS services |

**Service structure**:
```yaml
ddns_gateway_services:
  - name: cloud-ddns
    provider: cloudflare
    domain: cloud.example.com
    zone_id: "{{ vault_cf_zone_id }}"
    api_token: "{{ vault_cf_api_token }}"
    ip_source: ec2_imdsv2        # ec2_imdsv2, url, command
    # ip_url: "http://checkip.amazonaws.com"  # for url source
    # ip_command: "curl -s ..."               # for command source
    ttl: 300
    proxied: false
```

---

### webui - LuCI HTTPS Configuration

Configures uhttpd web server with HTTPS for LuCI access.

**Tags**: `webui`, `webui_packages`, `webui_certs`, `webui_config`

**Key Variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `webui_install_luci` | `true` | Install LuCI |
| `webui_copy_certs` | `false` | Deploy custom certificates |
| `webui_cert_src` | - | Source certificate path |
| `webui_key_src` | - | Source key path |
| `webui_cert_path` | `/etc/uhttpd.crt` | Destination cert path |
| `webui_key_path` | `/etc/uhttpd.key` | Destination key path |
| `webui_listen_ip` | `0.0.0.0` | Listen address |
| `webui_http_port` | `80` | HTTP port |
| `webui_https_port` | `443` | HTTPS port |
| `webui_redirect_https` | `true` | Redirect HTTP to HTTPS |

---

## Plugins

### UCI Module (`harley.openwrt.uci`)

Manages OpenWRT UCI configuration files directly. Supports get/set/delete operations on named and anonymous sections.

**Parameters**:

| Parameter | Aliases | Required | Description |
|-----------|---------|----------|-------------|
| `package` | `p` | Yes | UCI package name |
| `section` | `s` | No | Named section |
| `type` | - | No | Section type (for creation) |
| `index` | - | No | Anonymous section index (default: 0) |
| `name` | `key` | No | Option name |
| `value` | `val` | No | Option value |
| `item` | - | No | `option` or `list` (default: option) |
| `state` | - | No | `present` or `absent` (default: present) |
| `create` | - | No | Create if not exists (default: yes) |

**Examples**:
```yaml
# Set named section option
- harley.openwrt.uci:
    p: dhcp
    s: lan
    name: start
    val: 100

# Add to a list
- harley.openwrt.uci:
    p: dhcp
    s: lan
    name: dhcp_option
    val: "4,192.168.1.1"
    item: list

# Create named section with type
- harley.openwrt.uci:
    p: dhcp
    s: myhost
    type: host
    name: ip
    val: "192.168.1.50"

# Delete option
- harley.openwrt.uci:
    p: dhcp
    s: myhost
    name: ip
    state: absent

# Set anonymous section option (by type + index)
- harley.openwrt.uci:
    p: dhcp
    type: dnsmasq
    index: 0
    name: domain
    val: example.com
```

**Notes**:
- Supports `--check` mode and `--diff` mode
- Automatically commits changes after each operation
- Anonymous sections are accessed via type + index

### Filter: `host_names_to_ip_addresses`

Converts a list of hostnames to their IP addresses from inventory hostvars.

**Usage**:
```yaml
{{ groups['lan'] | host_names_to_ip_addresses(hostvars) }}
```

---

## Inventory Convention

The collection supports an optional inventory convention that enables automatic variable mapping from inventory host/group variables to role variables.

### Convention Variables

**Host variables**:

| Variable | Required | Description |
|----------|----------|-------------|
| `ip_address` | Yes | Host's IP address |
| `mac_address` | For DHCP | MAC address (for static leases) |
| `cname` | No | DNS CNAME alias |
| `fqdns_name` | No | FQDN (auto-generated if not set) |

**Group variables**:

| Variable | Required | Description |
|----------|----------|-------------|
| `dns_domain` | Recommended | Local domain (e.g., `home.lan`) |

### Inventory Adapter

Include the adapter in pre_tasks to automatically build `dhcp_dns_*` variables from inventory:

```yaml
- hosts: router
  collections:
    - harley.openwrt

  pre_tasks:
    - name: Build dhcp_dns variables from inventory
      ansible.builtin.include_tasks:
        file: "{{ (lookup('ansible.builtin.config', 'COLLECTIONS_PATH') | split(':') | first) }}/ansible_collections/harley/openwrt/playbooks/includes/inventory_to_dhcp_dns.yml"
      tags: [dhcp_dns]

  roles:
    - role: dhcp_dns
      vars:
        dhcp_dns_domain: "{{ dns_domain }}"
      tags: [dhcp_dns]
```

**Limit to specific group**:
```yaml
pre_tasks:
  - name: Build dhcp_dns variables from inventory
    ansible.builtin.include_tasks:
      file: .../inventory_to_dhcp_dns.yml
    vars:
      inventory_adapter_group: lan
```

**Produced variables**:
- `dhcp_dns_static_leases` - hosts with `mac_address` set
- `dhcp_dns_hosts` - all hosts with `ip_address`
- `dhcp_dns_cnames` - hosts with `cname` set

---

## Common Workflows

### Workflow 1: Fresh Router Setup

```yaml
- hosts: router
  gather_facts: false
  become: true
  collections:
    - harley.openwrt

  roles:
    - role: base
      vars:
        base_ansible_authorized_key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"
        base_ansible_password: "{{ vault_ansible_password }}"
      tags: [base]

    - role: network
      vars:
        network_wan_proto: pppoe
        network_wan_pppoe_username: "{{ vault_isp_user }}"
        network_wan_pppoe_password: "{{ vault_isp_pass }}"
        network_lan_ipaddr: "10.1.0.1"
      tags: [network]

    - role: firewall
      tags: [firewall]

    - role: dhcp_dns
      vars:
        dhcp_dns_domain: home.lan
      tags: [dhcp_dns]

    - role: webui
      tags: [webui]
```

### Workflow 2: Site-to-Site VPN (OpenWRT to Cloud Gateway)

**OpenWRT side** (site-to-site initiator):
```yaml
- role: ipsec
  vars:
    ipsec_connections:
      - name: to-cloud
        type: tunnel
        auto: start
        keyexchange: ikev2
        left: "%defaultroute"
        leftid: "home.example.com"
        leftsubnet: "10.1.0.0/24"
        leftauth: pubkey
        leftcert: home.crt
        right: "cloud.example.com"
        rightid: "cloud.example.com"
        rightsubnet: "10.2.0.0/24"
        rightauth: pubkey
        leftupdown: "/etc/ipsec.d/ipsec-updown.sh"
        mark: "42"
        vti_if: vti0
        vti_local_ip: "10.10.0.1"
        vti_remote_ip: "10.10.0.2"
  tags: [ipsec]

- role: firewall
  vars:
    firewall_ipsec_enabled: true
    firewall_extra_zones:
      - name: vpn
        input: ACCEPT
        output: ACCEPT
        forward: ACCEPT
        network: vti0
    firewall_extra_forwardings:
      - { src: vpn, dest: lan }
      - { src: lan, dest: vpn }
  tags: [firewall]
```

**Cloud gateway side** (site-to-site responder):
```yaml
- hosts: cloud_gateway
  become: true
  collections:
    - harley.openwrt

  roles:
    - role: ipsec_gateway
      vars:
        ipsec_connections:
          - name: from-home
            type: tunnel
            auto: add
            keyexchange: ikev2
            left: "%defaultroute"
            leftid: "cloud.example.com"
            leftsubnet: "10.2.0.0/24"
            leftauth: pubkey
            leftcert: cloud.crt
            right: "%any"
            rightid: "home.example.com"
            rightsubnet: "10.1.0.0/24"
            rightauth: pubkey
            leftupdown: "/etc/ipsec.d/ipsec-updown.sh"
            mark: "42"
            vti_if: vti0
            vti_local_ip: "10.10.0.2"
            vti_remote_ip: "10.10.0.1"

    - role: ddns_gateway
      vars:
        ddns_gateway_enabled: true
        ddns_gateway_services:
          - name: cloud-dns
            provider: cloudflare
            domain: cloud.example.com
            zone_id: "{{ vault_cf_zone_id }}"
            api_token: "{{ vault_cf_token }}"
            ip_source: ec2_imdsv2
```

### Workflow 3: ACME + HTTPS Web UI

```yaml
- role: acme
  vars:
    acme_email: admin@example.com
    acme_domain: "*.home.example.com"
    acme_dns_provider: dns_cf
    acme_cf_token: "{{ vault_cf_token }}"
    acme_cf_zone_id: "{{ vault_cf_zone_id }}"
  tags: [acme]

- role: webui
  vars:
    webui_copy_certs: true
    webui_cert_src: "/etc/acme/*.home.example.com_ecc/fullchain.cer"
    webui_key_src: "/etc/acme/*.home.example.com_ecc/*.home.example.com.key"
    webui_redirect_https: true
  tags: [webui]
```

### Workflow 4: Tag-Based Partial Deployment

```bash
# Only update DHCP/DNS configuration
ansible-playbook -i inventory.yml site.yml --tags dhcp_dns

# Only update firewall rules
ansible-playbook -i inventory.yml site.yml --tags firewall

# Check mode (dry run) with diff
ansible-playbook -i inventory.yml site.yml --check --diff --tags network

# Use vault for secrets
ansible-playbook -i inventory.yml site.yml --vault-password-file .vault_pass.txt
```

---

## Playbook Structure Pattern

The recommended playbook structure:

```yaml
- hosts: router
  gather_facts: false        # OpenWRT may not have full facts
  become: true               # Need root for UCI/opkg
  collections:
    - harley.openwrt         # Resolve roles from collection

  pre_tasks:
    # Optional: inventory adapter for DHCP/DNS
    - name: Build dhcp_dns variables from inventory
      ansible.builtin.include_tasks:
        file: "{{ ... }}/inventory_to_dhcp_dns.yml"
      tags: [dhcp_dns]

    # Optional: enrich variables
    - name: Add extra CNAME records
      ansible.builtin.set_fact:
        dhcp_dns_cnames: "{{ dhcp_dns_cnames + extra_cnames }}"
      tags: [dhcp_dns]

  roles:
    - role: base
      tags: [base]
    - role: network
      vars: { ... }
      tags: [network]
    - role: firewall
      vars: { ... }
      tags: [firewall]
    - role: dhcp_dns
      vars: { ... }
      tags: [dhcp_dns]
    # ... more roles
```

### Recommended Inventory Layout

```
ansible/
├── site.yml                    # Main playbook
├── inventory.yml               # Inventory file
├── collections/
│   └── requirements.yml        # Collection dependencies
├── group_vars/
│   ├── all.yml                 # Global: dns_domain, etc.
│   ├── lan.yml                 # LAN hosts: network prefix, etc.
│   └── wan.yml                 # WAN hosts
├── host_vars/
│   ├── router/
│   │   ├── vars.yml            # Router config
│   │   └── vault.yml           # Secrets (ansible-vault)
│   ├── server1.yml             # ip_address, mac_address
│   └── server2.yml             # ip_address, mac_address, cname
└── .vault_pass.txt             # Vault password (gitignored)
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ssh: Connection refused` on fresh router | Use `base` role with `ansible_connection: local` or connect to 192.168.1.1 first |
| `opkg: not found` | Ensure target is actually OpenWRT |
| Python not installed on router | Run `base` role first with `base_install_python: true` |
| UCI changes not taking effect | Handlers restart services; run with `--flush-handlers` if needed |
| WiFi not connecting | Check `encryption` matches client, verify `country` code is correct |
| IPsec tunnel not establishing | Check certificates, verify `leftid`/`rightid` match cert CNs, check time sync |
| ACME cert not issuing | Verify DNS provider credentials, try `acme_use_staging: true` first |
| AppArmor blocking charon logs | Ensure `ipsec_gateway_apparmor: true` is set |
| DDNS not updating | Check provider credentials, verify IP source method |
| `become` failures | Ensure `base_install_sudo: true` was run, or use `ansible_become_method: su` |

## Important Notes for Claude

1. **OpenWRT uses UCI** - not standard Linux config files. The `uci` module and Jinja2 templates generate UCI-format configs.
2. **OpenWRT has limited resources** - keep tasks efficient, avoid unnecessary package installs.
3. **Two target platforms** - roles without `_gateway` suffix target OpenWRT; roles with `_gateway` target Ubuntu/Debian.
4. **Secrets belong in vault** - always suggest `ansible-vault` for passwords, API tokens, WiFi keys, and certificate private keys.
5. **Tags enable selective runs** - every role supports granular tags for partial deployments.
6. **The base role runs first** - it bootstraps Python/SSH which Ansible needs for everything else.
7. **IPsec roles share variables** - `ipsec` and `ipsec_gateway` use the same `ipsec_*` connection variable format.
8. **Inventory adapter is optional** - users can define `dhcp_dns_*` variables directly instead of using the convention.
9. **Check mode works** - the UCI module supports `--check` and `--diff` for safe dry runs.
10. **Templates are Jinja2** - found in `roles/<role>/templates/`, they generate UCI or Linux config files.

## Source Code Structure

```
ansible-collection-openwrt/
├── galaxy.yml                              # Collection metadata
├── README.md                               # Main documentation
├── docs/
│   └── inventory-convention.md             # Inventory variable conventions
├── plugins/
│   ├── modules/uci.py                      # UCI configuration module
│   └── filter/hostnames_to_vars.py         # Hostname filter
├── playbooks/includes/
│   └── inventory_to_dhcp_dns.yml           # Inventory adapter
└── roles/
    ├── base/
    │   ├── tasks/main.yml                  # Orchestrates sub-tasks
    │   ├── tasks/detect_connection.yml
    │   ├── tasks/install_python3.yml
    │   ├── tasks/install_pip3.yml
    │   ├── tasks/install_sftp.yml
    │   ├── tasks/install_user_management.yml
    │   ├── tasks/create_ansible_user.yml
    │   ├── tasks/update_packages.yml
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── network/
    │   ├── tasks/{main,configure_wan,configure_lan,configure_wifi_radio}.yml
    │   ├── defaults/main.yml
    │   ├── handlers/main.yml
    │   └── README.md
    ├── firewall/
    │   ├── tasks/main.yml
    │   ├── templates/firewall.j2
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── dhcp_dns/
    │   ├── tasks/{main,static_lease,dns_host,dns_cname}.yml
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── ipsec/
    │   ├── tasks/main.yml
    │   ├── templates/{ipsec.conf,ipsec.secrets,strongswan.conf}.j2
    │   ├── files/ipsec-updown.sh
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── ipsec_gateway/
    │   ├── tasks/main.yml
    │   ├── templates/{ipsec.conf,ipsec.secrets,strongswan.conf,charon.conf,charon-logging.conf}.j2
    │   ├── files/ipsec-updown.sh
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── acme/
    │   ├── tasks/main.yml
    │   ├── templates/{acme,credentials.env}.j2
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── ddns/
    │   ├── tasks/main.yml
    │   ├── templates/ddns.j2
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    ├── ddns_gateway/
    │   ├── tasks/main.yml
    │   ├── templates/{ddns-update.sh,ddns-update.service,ddns-update.timer}.j2
    │   ├── defaults/main.yml
    │   └── handlers/main.yml
    └── webui/
        ├── tasks/main.yml
        ├── defaults/main.yml
        └── handlers/main.yml
```

## Keywords for Detection

Ansible, OpenWRT, harley.openwrt, router configuration, UCI, uci module, opkg, LuCI, uhttpd, dnsmasq, DHCP, DNS, static lease, CNAME, A record, firewall zone, iptables, StrongSwan, IPsec, VPN, site-to-site, road-warrior, IKE, ESP, VTI, tunnel, ACME, Let's Encrypt, acme.sh, DNS-01, Cloudflare, certificate, DDNS, dynamic DNS, ddns-scripts, systemd timer, WiFi, WAN, LAN, PPPoE, network interface, OpenWRT base setup, ansible-galaxy collection, harley openwrt collection, inventory convention, inventory adapter, dhcp_dns, ipsec_gateway, ddns_gateway, charon, strongswan.conf, ipsec.conf
