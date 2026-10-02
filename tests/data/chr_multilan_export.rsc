# 2026-10-02 08:16:43 by RouterOS 7.24.4
# sanitized from a real CHR: documentation IP ranges, placeholder keys
#
/interface ethernet set [ find default-name=ether1 ] disable-running-check=no
/interface ethernet set [ find default-name=ether2 ] disable-running-check=no
/interface ethernet set [ find default-name=ether3 ] disable-running-check=no
/interface ethernet set [ find default-name=ether4 ] arp=proxy-arp disable-running-check=no mtu=1400
/interface wireguard add listen-port=51820 mtu=1400 name=wg1 private-key="PLACEHOLDER-KEY-1="
/interface wireguard add listen-port=13231 mtu=1420 name=wg50 private-key="PLACEHOLDER-KEY-2="
/interface vlan add disabled=yes interface=ether1 name=vlan4000-wan vlan-id=4000
/interface list add name=WAN
/interface list add name=LAN
/ip pool add name=dhcp_pool0 ranges=10.200.30.2-10.200.30.254
/ip pool add name=sm-lan-pool ranges=10.20.30.100-10.20.30.199
/ip dhcp-server add address-pool=dhcp_pool0 interface=ether4 name=dhcp1
/ip dhcp-server add address-pool=sm-lan-pool interface=ether3 lease-time=1d name=sm-dhcp-lan
/interface list member add interface=wg1 list=LAN
/interface list member add disabled=yes interface=ether2 list=WAN
/interface list member add interface=ether1 list=WAN
/interface list member add interface=ether3 list=LAN
/interface list member add interface=ether4 list=LAN
/interface wifi cap set caps-man-addresses=198.51.100.237 discovery-interfaces=*1 enabled=yes
/ip address add address=198.51.100.237/28 interface=ether1 network=198.51.100.224
/ip address add address=172.16.13.4 interface=wg1 network=172.16.13.1
/ip address add address=203.0.113.105/24 interface=ether2 network=203.0.113.0
/ip address add address=10.20.30.1/24 interface=ether3 network=10.20.30.0
/ip address add address=198.51.100.239/28 comment=imap disabled=yes interface=*1 network=198.51.100.224
/ip address add address=198.51.100.226/28 comment=Cloudpanel interface=vlan4000-wan network=198.51.100.224
/ip address add address=10.200.30.1/24 comment="VSwitch Intern" interface=ether4 network=10.200.30.0
/ip address add address=172.16.50.1/24 interface=wg50 network=172.16.50.0
/ip dhcp-client
# Interface not active
add interface=*1 name=client1
/ip dhcp-server network add address=10.20.30.0/24 dns-server=1.1.1.1 gateway=10.20.30.1
/ip dhcp-server network add address=10.200.30.0/24 dns-server=1.1.1.1 gateway=10.200.30.1
/ip dns set allow-remote-requests=yes servers=1.1.1.1,8.8.8.8
/ip firewall address-list add address=192.0.2.0/24 comment=CHINA list=CountryIPBlocks
/ip firewall address-list add address=198.51.100.230 comment="login failure" list=list_failed_attempt
/ip firewall filter add action=accept chain=input comment="Allow Wireguard from All" dst-port=13231 protocol=udp
/ip firewall filter add action=accept chain=input log=yes log-prefix=Lager_ src-address=192.0.2.142
/ip firewall filter add action=drop chain=forward src-address-list=CountryIPBlocks
/ip firewall filter
# ether1 not ready
add action=accept chain=input in-interface=*1 log=yes
/ip firewall filter add action=accept chain=forward log-prefix=intern src-address=10.20.30.0/24
/ip firewall filter add action=accept chain=input log-prefix=intern src-address=10.20.30.0/24
/ip firewall filter add action=accept chain=input connection-state=established,related,untracked
/ip firewall filter add action=jump chain=forward comment="jump to ICMP filters" disabled=yes jump-target=icmp protocol=icmp
/ip firewall filter add action=drop chain=input comment="Invalide TCP Pakete" connection-state=invalid
/ip firewall filter add action=drop chain=input comment="Block Portscan" protocol=tcp psd=20,3s,10,2
/ip firewall filter add action=return chain=detect-ddos dst-limit=32,32,src-and-dst-addresses/10s
/ip firewall filter add action=add-src-to-address-list address-list=ddos-attackers address-list-timeout=10m chain=detect-ddos
/ip firewall filter add action=drop chain=input src-address-list=list_failed_attempt
/ip firewall filter add action=accept chain=input protocol=icmp
/ip firewall filter add action=drop chain=input log-prefix=DROP_INPUT_
/ip firewall filter add action=fasttrack-connection chain=forward comment=FastTrack connection-state=established,related
/ip firewall filter add action=accept chain=forward connection-state=established,related
/ip firewall filter
add action=drop chain=forward comment="Drop incoming packets that are not NAT`ted" connection-nat-state=!dstnat connection-state=new in-interface=ether1 log=yes log-prefix=!NAT
/ip firewall filter add action=drop chain=icmp comment="deny all other types"
/ip firewall filter add action=drop chain=input
/ip firewall filter
add action=accept chain=input in-interface=ether1 log=yes
/ip firewall filter add action=accept chain=input comment="Allow WireGuard" dst-port=54321 protocol=udp
/ip firewall mangle add action=change-mss chain=forward new-mss=clamp-to-pmtu protocol=tcp tcp-flags=syn
/ip firewall nat add action=masquerade chain=srcnat log=yes log-prefix=nat_ out-interface=ether4
/ip firewall nat add action=src-nat chain=srcnat out-interface=ether1 src-address=10.200.30.0/24 to-addresses=198.51.100.237
/ip firewall nat add action=masquerade chain=srcnat log=yes log-prefix=nat_ out-interface-list=WAN src-address=10.20.30.0/24
/ip firewall nat add action=dst-nat chain=dstnat comment=Cloudpanel dst-address=198.51.100.226 dst-port=443 protocol=tcp to-addresses=10.200.30.101 to-ports=443
/ip firewall raw add action=drop chain=prerouting comment="Block Ping Flood" limit=!1,1:packet protocol=icmp
/ip firewall raw add action=drop chain=prerouting comment="Drop IPv64 Blocklist" src-address-list=IPv64-Blocklist
/ip route add dst-address=0.0.0.0/0 gateway=198.51.100.225
/ip route add disabled=no dst-address=0.0.0.0/0 gateway=198.51.100.225%vlan4000-wan routing-table=main
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www-ssl certificate=rest disabled=no
/system identity set name=gw2.example.net
/system ntp client set enabled=yes
