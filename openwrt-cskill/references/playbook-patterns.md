# Playbook Patterns and Examples

Common patterns for using the `harley.openwrt` collection in Ansible playbooks.

## Playbook Declaration

Always declare the collection at the play level:

```yaml
- hosts: router
  gather_facts: false
  become: true
  collections:
    - harley.openwrt
```

**Key points**:
- `gather_facts: false` - OpenWRT may not have full Python/setup module on first run
- `become: true` - UCI and opkg need root
- `collections` - allows referring to roles by short name (e.g., `network` instead of `harley.openwrt.network`)

## Variable Organization

### Group Variables Pattern

```yaml
# group_vars/all.yml - Global settings
dns_domain: home.lan
lan_network_prefix: "10.1.0"
lan_netmask: "255.255.255.0"

# group_vars/lan.yml - LAN host defaults
ip_address: "{{ lan_network_prefix }}.{{ eth_ip_address_suffix }}"
mac_address: "{{ eth_mac_address }}"

# group_vars/wifi.yml - WiFi host defaults
ip_address: "{{ lan_network_prefix }}.{{ wifi_ip_address_suffix }}"
mac_address: "{{ wifi_mac_address }}"
```

### Host Variables Pattern

```yaml
# host_vars/server1/vars.yml
eth_ip_address_suffix: 10
eth_mac_address: "aa:bb:cc:dd:ee:ff"
cname: files    # optional CNAME alias

# host_vars/router/vars.yml
eth_ip_address_suffix: 1
wan_ip_address_suffix: 2
eth_mac_address: "5a:ef:68:0e:1c:ba"
wan_mac_address: "58:ef:68:0e:1c:ba"

# host_vars/router/vault.yml (encrypted)
vault_isp_password: "secret123"
vault_wifi_password: "wifipass456"
vault_cloudflare_token: "cf-token-789"
```

### Using Vault

```bash
# Create vault-encrypted file
ansible-vault create host_vars/router/vault.yml

# Edit vault file
ansible-vault edit host_vars/router/vault.yml

# Run with vault
ansible-playbook -i inventory.yml site.yml --vault-password-file .vault_pass.txt

# Or prompt for password
ansible-playbook -i inventory.yml site.yml --ask-vault-pass
```

## Inventory Adapter Pattern

The adapter converts inventory convention variables into role-specific variables:

```yaml
pre_tasks:
  # Step 1: Build base DHCP/DNS variables from inventory
  - name: Build dhcp_dns variables from inventory
    ansible.builtin.include_tasks:
      file: "{{ (lookup('ansible.builtin.config', 'COLLECTIONS_PATH') | split(':') | first) }}/ansible_collections/harley/openwrt/playbooks/includes/inventory_to_dhcp_dns.yml"
    vars:
      inventory_adapter_group: lan   # optional: limit to group
    tags: [dhcp_dns]

  # Step 2: Enrich with additional records (optional)
  - name: Add application CNAME records
    ansible.builtin.set_fact:
      dhcp_dns_cnames: "{{ dhcp_dns_cnames + app_cnames }}"
    vars:
      app_cnames:
        - { alias: "dashboard", target: "server1", name: "dashboard_cname" }
        - { alias: "git", target: "server2", name: "git_cname" }
    tags: [dhcp_dns]
```

**For local development** (collection installed to project directory):
```yaml
pre_tasks:
  - name: Build dhcp_dns variables from inventory
    ansible.builtin.include_tasks:
      file: "{{ playbook_dir }}/collections/ansible_collections/harley/openwrt/playbooks/includes/inventory_to_dhcp_dns.yml"
    tags: [dhcp_dns]
```

## Role Composition Patterns

### Full Router Configuration

```yaml
roles:
  - role: base
    vars:
      base_ansible_authorized_key: "{{ lookup('file', '~/.ssh/id_ed25519.pub') }}"
      base_ansible_password: "{{ vault_ansible_password }}"
    tags: [base]

  - role: network
    vars:
      network_wan_proto: pppoe
      network_wan_pppoe_username: "{{ vault_isp_username }}"
      network_wan_pppoe_password: "{{ vault_isp_password }}"
      network_lan_ipaddr: "{{ lan_network_prefix }}.1"
      network_lan_netmask: "{{ lan_netmask }}"
      network_wifi_enabled: true
      network_wifi_radios:
        - radio: radio0
          country: "{{ wifi_radio0_country }}"
          channel: "{{ wifi_radio0_channel }}"
          htmode: "{{ wifi_radio0_htmode }}"
          ssid: "{{ wifi_radio0_ssid }}"
          encryption: sae-mixed
          key: "{{ vault_wifi_radio0_password }}"
        - radio: radio1
          country: "{{ wifi_radio1_country }}"
          channel: "{{ wifi_radio1_channel }}"
          htmode: "{{ wifi_radio1_htmode }}"
          ssid: "{{ wifi_radio1_ssid }}"
          encryption: sae-mixed
          key: "{{ vault_wifi_radio1_password }}"
    tags: [network]

  - role: dhcp_dns
    vars:
      dhcp_dns_domain: "{{ dns_domain }}"
      dhcp_dns_lan_start: 100
      dhcp_dns_lan_limit: 150
      dhcp_dns_lan_options:
        - "6,{{ lan_network_prefix }}.1"
        - "15,{{ dns_domain }}"
    tags: [dhcp_dns]

  - role: firewall
    tags: [firewall]

  - role: acme
    vars:
      acme_email: admin@example.com
      acme_domain: "*.{{ dns_domain }}"
      acme_dns_provider: dns_cf
      acme_cf_token: "{{ vault_cloudflare_token }}"
      acme_cf_zone_id: "{{ vault_cloudflare_zone_id }}"
    tags: [acme]

  - role: webui
    vars:
      webui_redirect_https: true
    tags: [webui]
```

### VPN-Enabled Router

```yaml
roles:
  - role: ipsec
    vars:
      ipsec_ca_certs:
        - { src: "files/certs/ca.crt", dest: "ca.crt" }
      ipsec_host_certs:
        - { src: "files/certs/router.crt", dest: "router.crt" }
      ipsec_private_keys:
        - { src: "files/certs/router.key", dest: "router.key" }
      ipsec_rsa_key: router.key
      ipsec_connections:
        - name: to-cloud
          type: tunnel
          auto: start
          keyexchange: ikev2
          left: "%defaultroute"
          leftid: "home.example.com"
          leftsubnet: "10.1.0.0/24"
          leftauth: pubkey
          leftcert: router.crt
          right: "cloud.example.com"
          rightid: "cloud.example.com"
          rightsubnet: "10.2.0.0/24"
          rightauth: pubkey
          leftupdown: "/etc/ipsec.d/ipsec-updown.sh"
          mark: "42"
          vti_if: vti0
          vti_local_ip: "10.10.0.1"
          vti_remote_ip: "10.10.0.2"
          vti_local_subnet: "10.1.0.0/24"
          vti_remote_subnet: "10.2.0.0/24"
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

  - role: ddns
    vars:
      ddns_enabled: true
      ddns_services:
        - name: home-ddns
          provider: "cloudflare.com-v4"
          domain: "home.example.com"
          username: "{{ vault_cf_email }}"
          password: "{{ vault_cf_token }}"
          ip_source: web
          ip_url: "http://checkip.amazonaws.com"
          interface: wan
    tags: [ddns]
```

### Cloud Gateway Playbook

```yaml
- hosts: cloud_gateway
  become: true
  collections:
    - harley.openwrt

  roles:
    - role: ipsec_gateway
      vars:
        ipsec_ca_certs:
          - { src: "files/certs/ca.crt", dest: "ca.crt" }
        ipsec_host_certs:
          - { src: "files/certs/cloud.crt", dest: "cloud.crt" }
        ipsec_private_keys:
          - { src: "files/certs/cloud.key", dest: "cloud.key" }
        ipsec_rsa_key: cloud.key
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
            vti_local_subnet: "10.2.0.0/24"
            vti_remote_subnet: "10.1.0.0/24"
      tags: [ipsec_gateway]

    - role: ddns_gateway
      vars:
        ddns_gateway_enabled: true
        ddns_gateway_services:
          - name: cloud-ddns
            provider: cloudflare
            domain: cloud.example.com
            zone_id: "{{ vault_cf_zone_id }}"
            api_token: "{{ vault_cf_token }}"
            ip_source: ec2_imdsv2
            ttl: 300
      tags: [ddns_gateway]
```

## Execution Patterns

### Tag-Based Partial Runs

```bash
# Only update DNS records
ansible-playbook -i dev.yml site.yml --tags dhcp_dns

# Only update firewall
ansible-playbook -i dev.yml site.yml --tags firewall

# Multiple tags
ansible-playbook -i dev.yml site.yml --tags "network,firewall"

# Skip a role
ansible-playbook -i dev.yml site.yml --skip-tags base
```

### Safe Dry-Run

```bash
# Check mode with diff output
ansible-playbook -i dev.yml site.yml --check --diff

# Limit to specific host
ansible-playbook -i dev.yml site.yml --limit router --check --diff
```

### Multi-Environment

```bash
# Development inventory
ansible-playbook -i development.yml site.yml --vault-password-file .vault_pass.txt

# Production (cloud) inventory
ansible-playbook -i cloud.yml cloud-gateway.yml --vault-password-file .vault_pass.txt
```

## UCI Module Direct Usage

For custom tasks not covered by roles:

```yaml
tasks:
  - name: Set custom dnsmasq option
    harley.openwrt.uci:
      p: dhcp
      type: dnsmasq
      name: rebind_protection
      val: "0"

  - name: Add DNS forwarder
    harley.openwrt.uci:
      p: dhcp
      type: dnsmasq
      name: server
      val: "/internal.corp/10.0.0.1"
      item: list

  - name: Create static host entry
    harley.openwrt.uci:
      p: dhcp
      s: mydevice
      type: host
      name: ip
      val: "192.168.1.50"
    notify: restart dnsmasq
```

## Filter Plugin Usage

```yaml
# Convert group hostnames to IPs
- name: Get all LAN host IPs
  debug:
    msg: "{{ groups['lan'] | host_names_to_ip_addresses(hostvars) }}"
```

## Collection Installation in Projects

### requirements.yml

```yaml
collections:
  # From GitHub (production)
  - name: git+https://github.com/harley-systems/ansible-collection-openwrt.git
    type: git

  # Or from Galaxy (when published)
  # - name: harley.openwrt
  #   version: ">=0.1.0"
```

### Install commands

```bash
# Install from requirements
ansible-galaxy collection install -r collections/requirements.yml

# Install from local source (development)
ansible-galaxy collection install ~/src/ansible-collection-openwrt -p ./collections --force

# Install from GitHub directly
ansible-galaxy collection install git+https://github.com/harley-systems/ansible-collection-openwrt.git
```
