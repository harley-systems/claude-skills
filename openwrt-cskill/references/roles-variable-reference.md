# Roles Variable Reference

Complete variable reference for all `harley.openwrt` roles with types, defaults, and descriptions.

## base

```yaml
# User configuration
base_ansible_user: ansible              # str - Username
base_ansible_user_uid: 1000             # int - User ID
base_ansible_user_groups: "adm,ansible,wheel"  # str - Comma-separated groups
base_ansible_user_shell: /bin/ash       # str - Login shell
base_ansible_user_home: /home/ansible   # str - Home directory
base_ansible_authorized_key: ""         # str - REQUIRED: SSH public key content
base_ansible_password: ""               # str - REQUIRED: User password

# Feature toggles
base_install_python: true               # bool - Install Python 3
base_install_pip: true                  # bool - Install pip3
base_install_sftp: true                 # bool - Install openssh-sftp-server
base_install_sudo: true                 # bool - Install sudo/useradd/groupadd
base_update_packages: true              # bool - Run opkg update
```

## network

```yaml
# WAN
network_wan_enabled: true               # bool - Configure WAN interface
network_wan_proto: dhcp                 # str - dhcp|pppoe|static
network_wan_ifname: wan                 # str - Interface name
network_wan_device: "eth1.2"            # str - Device name (hardware-specific)
network_wan_pppoe_username: ""          # str - PPPoE username (if pppoe)
network_wan_pppoe_password: ""          # str - PPPoE password (if pppoe)
network_wan_pppoe_keepalive: "5 5"      # str - PPPoE keepalive "interval retries"
network_wan_ipaddr: ""                  # str - Static IP (if static)
network_wan_netmask: ""                 # str - Static netmask (if static)
network_wan_gateway: ""                 # str - Static gateway (if static)
network_wan_dns: ""                     # str - Static DNS servers (if static)
network_wan_ipv6: auto                  # str - auto|disable

# LAN
network_lan_enabled: true               # bool - Configure LAN interface
network_lan_ifname: lan                 # str - Interface name
network_lan_proto: static               # str - Protocol (usually static)
network_lan_ipaddr: "192.168.1.1"       # str - LAN IP address
network_lan_netmask: "255.255.255.0"    # str - LAN netmask
network_lan_dns: ""                     # str - DNS for LAN interface

# WiFi
network_wifi_enabled: false             # bool - Configure WiFi
network_wifi_radios: []                 # list - Radio configurations (see below)

# Each radio in network_wifi_radios:
# - radio: radio0                       # str - Radio device name
#   country: US                         # str - Regulatory country code
#   channel: auto                       # str/int - Channel or 'auto'
#   htmode: VHT80                       # str - HT20|HT40|VHT20|VHT40|VHT80|VHT160
#   txpower: 20                         # int - Transmit power in dBm
#   ssid: NetworkName                   # str - SSID
#   encryption: sae-mixed               # str - none|psk2|sae|sae-mixed
#   key: "password"                     # str - WiFi password
#   mode: ap                            # str - ap|sta|adhoc
#   disabled: false                     # bool - Disable this radio
#   legacy_rates: false                 # bool - Enable legacy rates
#   hidden: false                       # bool - Hide SSID
#   distance: ""                        # str - Optimize for distance (meters)
#   macaddr: ""                         # str - Override MAC address
```

## firewall

```yaml
# Global policies
firewall_syn_flood: true                # bool - SYN flood protection
firewall_input: ACCEPT                  # str - ACCEPT|REJECT|DROP
firewall_output: ACCEPT                 # str - ACCEPT|REJECT|DROP
firewall_forward: REJECT                # str - ACCEPT|REJECT|DROP

# Zones (list of dicts)
firewall_zones:
  - name: lan                           # str - Zone name
    input: ACCEPT                       # str - Input policy
    output: ACCEPT                      # str - Output policy
    forward: ACCEPT                     # str - Forward policy
    network: lan                        # str - Network interface(s)
    # Optional per zone:
    # masq: false                       # bool - Enable masquerade/NAT
    # mtu_fix: false                    # bool - MSS clamping
  - name: wan
    input: REJECT
    output: ACCEPT
    forward: REJECT
    masq: true
    mtu_fix: true
    network: "wan wan6"

# Forwarding rules (list of dicts)
firewall_forwardings:
  - src: lan                            # str - Source zone
    dest: wan                           # str - Destination zone

# Extra zones and forwardings (for VPN, guest, etc.)
firewall_extra_zones: []                # list - Additional zones
firewall_extra_forwardings: []          # list - Additional forwardings

# Custom rules (list of dicts)
firewall_rules: []
# - name: Allow-SSH-WAN                 # str - Rule name
#   src: wan                            # str - Source zone
#   dest: lan                           # str - Destination zone (optional)
#   dest_port: 22                       # int/str - Destination port
#   src_port: ""                        # int/str - Source port
#   proto: tcp                          # str - tcp|udp|icmp|all
#   target: ACCEPT                      # str - ACCEPT|REJECT|DROP
#   src_ip: ""                          # str - Source IP (optional)
#   dest_ip: ""                         # str - Destination IP (optional)

# IPsec
firewall_ipsec_enabled: false           # bool - Add IPsec firewall rules
firewall_include_user: ""               # str - Path to user include script
```

## dhcp_dns

```yaml
# Domain
dhcp_dns_domain: lan                    # str - Local domain name

# LAN DHCP
dhcp_dns_lan_enabled: true              # bool - Enable DHCP on LAN
dhcp_dns_lan_interface: lan             # str - DHCP interface
dhcp_dns_lan_start: 100                 # int - Start offset from network base
dhcp_dns_lan_limit: 150                 # int - Number of addresses
dhcp_dns_lan_leasetime: "12h"           # str - Lease duration

# WAN DHCP
dhcp_dns_wan_enabled: false             # bool - Enable DHCP on WAN
dhcp_dns_wan_interface: wan             # str - WAN interface
dhcp_dns_wan_ignore: true               # bool - Ignore DHCP on WAN

# Records
dhcp_dns_static_leases: []              # list - Static DHCP leases
# - name: hostname                      # str - Hostname
#   mac: "aa:bb:cc:dd:ee:ff"            # str - MAC address
#   ip: "192.168.1.10"                  # str - IP address

dhcp_dns_hosts: []                      # list - DNS A records
# - name: hostname                      # str - Hostname
#   ip: "192.168.1.10"                  # str - IP address

dhcp_dns_cnames: []                     # list - DNS CNAME records
# - alias: git                          # str - CNAME alias
#   target: server1                     # str - Target hostname
#   name: git_cname                     # str - UCI section name (optional)

# Extra DHCP options (dnsmasq)
dhcp_dns_lan_options: []                # list of str
# - "6,192.168.1.1"                     # Option 6: DNS server
# - "15,home.lan"                       # Option 15: Domain name
```

## ipsec (OpenWRT) / ipsec_gateway (Linux) shared variables

```yaml
# Crypto proposals
ipsec_ike_default: "aes128-sha256-modp2048,aes256-sha384-modp4096,aes256-sha256-modp2048,aes128-sha256-modp3072"
ipsec_esp_default: "aes128-sha256-modp2048,aes256-sha384-modp4096,aes256-sha256,aes128-sha256"

# Dead Peer Detection
ipsec_dpdaction: clear                  # str - clear|hold|restart
ipsec_dpddelay: "300s"                  # str - DPD check interval
ipsec_dpd_timeout: "150s"              # str - DPD timeout

# Logging
ipsec_charondebug: ""                   # str - Charon debug categories

# Certificates
ipsec_ca_certs: []                      # list - CA certs to deploy
# - src: files/ca.crt                   # str - Local source path
#   dest: ca.crt                        # str - Filename on target

ipsec_host_certs: []                    # list - Host certificates
# - src: files/host.crt
#   dest: host.crt

ipsec_private_keys: []                  # list - Private keys
# - src: files/host.key
#   dest: host.key

ipsec_rsa_key: ""                       # str - Default RSA key filename

# Authentication
ipsec_psk_secrets: []                   # list - PSK secrets
# - left: "%any"                        # str - Left identity
#   right: "%any"                       # str - Right identity
#   psk: "shared_secret"               # str - Pre-shared key

# Connections (same format for both roles)
ipsec_connections: []
# - name: connection-name               # str - Connection name
#   type: tunnel                        # str - tunnel|transport
#   auto: start                         # str - start|add|route|ignore
#   keyexchange: ikev2                  # str - ikev1|ikev2
#   left: "%defaultroute"              # str - Local address
#   leftid: "my.host.com"             # str - Local identity
#   leftsubnet: "10.1.0.0/24"         # str - Local subnet
#   leftauth: pubkey                   # str - pubkey|psk|eap
#   leftcert: my.crt                   # str - Local certificate
#   right: "peer.host.com"            # str - Remote address (%any for responder)
#   rightid: "peer.host.com"          # str - Remote identity
#   rightsubnet: "10.2.0.0/24"        # str - Remote subnet
#   rightauth: pubkey                  # str - pubkey|psk|eap
#   ike: ""                            # str - IKE proposals (empty=default)
#   esp: ""                            # str - ESP proposals (empty=default)
#   # VTI (route-based VPN)
#   leftupdown: "/etc/ipsec.d/ipsec-updown.sh"
#   mark: "42"                         # str - XFRM mark
#   vti_if: vti0                       # str - VTI interface name
#   vti_local_ip: "10.10.0.1"        # str - VTI local IP
#   vti_remote_ip: "10.10.0.2"       # str - VTI remote IP
#   vti_local_subnet: "10.1.0.0/24"  # str - Local subnet for routing
#   vti_remote_subnet: "10.2.0.0/24" # str - Remote subnet for routing

# Kernel parameters
ipsec_sysctl_ip_forward: true           # bool - Enable IP forwarding
ipsec_sysctl_accept_redirects: false    # bool - Accept ICMP redirects
ipsec_sysctl_send_redirects: false      # bool - Send ICMP redirects
ipsec_sysctl_rp_filter: false           # bool - Reverse path filtering
ipsec_sysctl_accept_source_route: false # bool - Accept source routing

# OpenWRT-specific
ipsec_autostart: false                  # bool - Add to /etc/rc.local
```

## ipsec_gateway additional variables

```yaml
ipsec_gateway_packages:                 # list - Packages to install
  - strongswan
  - strongswan-pki
  - strongswan-swanctl
  - libcharon-extra-plugins
  - libcharon-extauth-plugins

ipsec_gateway_haveged: true             # bool - Install haveged (entropy)
ipsec_gateway_charon_log_path: "/var/log/charon.log"  # str - Log path
ipsec_gateway_charon_log_default: 1     # int - Log level (0-4)
ipsec_gateway_apparmor: true            # bool - Configure AppArmor
```

## acme

```yaml
acme_email: ""                          # str - REQUIRED: Let's Encrypt email
acme_domain: ""                         # str - REQUIRED: Domain (supports wildcards)
acme_dns_provider: dns_cf               # str - DNS provider (dns_cf, dns_gd, dns_aws, etc.)
acme_cf_token: ""                       # str - Cloudflare API token
acme_cf_zone_id: ""                     # str - Cloudflare Zone ID
acme_key_type: "ec-256"                 # str - ec-256|ec-384|rsa-2048|rsa-4096
acme_use_staging: false                 # bool - Use staging server
acme_configure_uhttpd: false            # bool - Auto-configure uhttpd with cert
```

## ddns

```yaml
ddns_enabled: false                     # bool - Enable DDNS
ddns_services: []                       # list - DDNS service configurations
# - name: myddns                        # str - Service identifier
#   provider: "cloudflare.com-v4"       # str - Provider name
#   domain: "home.example.com"          # str - Domain to update
#   username: ""                        # str - Provider username/email
#   password: ""                        # str - Provider password/token
#   ip_source: web                      # str - interface|network|web|script
#   ip_url: ""                          # str - URL for IP detection (if web)
#   ip_interface: ""                    # str - Interface (if interface)
#   ip_network: ""                      # str - Network (if network)
#   interface: wan                      # str - Trigger interface
#   check_interval: 10                  # int - Check interval value
#   check_unit: minutes                 # str - minutes|hours|seconds
#   force_interval: 72                  # int - Force update interval
#   force_unit: hours                   # str - minutes|hours|seconds
#   retry_interval: 60                  # int - Retry interval
#   retry_unit: seconds                 # str - minutes|hours|seconds
#   use_ipv6: false                     # bool - Use IPv6
```

## ddns_gateway

```yaml
ddns_gateway_enabled: false             # bool - Enable DDNS
ddns_gateway_packages:                  # list - Required packages
  - curl
  - python3
ddns_gateway_update_interval: "5min"    # str - Systemd timer interval
ddns_gateway_boot_delay: "30s"          # str - Delay after boot
ddns_gateway_script_dir: "/usr/local/bin"  # str - Script install path
ddns_gateway_services: []               # list - DDNS services
# - name: my-ddns                       # str - Service name
#   provider: cloudflare                # str - Provider (cloudflare)
#   domain: cloud.example.com           # str - FQDN to update
#   zone_id: ""                         # str - Cloudflare zone ID
#   api_token: ""                       # str - Cloudflare API token
#   ip_source: ec2_imdsv2              # str - ec2_imdsv2|url|command
#   ip_url: ""                          # str - URL (if url source)
#   ip_command: ""                      # str - Command (if command source)
#   ttl: 300                            # int - DNS TTL
#   proxied: false                      # bool - Cloudflare proxy
```

## webui

```yaml
webui_install_luci: true                # bool - Install LuCI
webui_copy_certs: false                 # bool - Deploy custom certificates
webui_cert_src: ""                      # str - Certificate source path
webui_key_src: ""                       # str - Key source path
webui_cert_path: "/etc/uhttpd.crt"      # str - Certificate destination
webui_key_path: "/etc/uhttpd.key"       # str - Key destination
webui_listen_ip: "0.0.0.0"             # str - Listen address
webui_http_port: 80                     # int - HTTP port
webui_https_port: 443                   # int - HTTPS port
webui_redirect_https: true              # bool - Redirect HTTP to HTTPS
```
