# 2026-09-26 10:12:03 by RouterOS 7.16.1
# software id =
#
/interface bridge
add name=bridge-lan
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no name=ether1-wan
set [ find default-name=ether2 ] disable-running-check=no
/interface wireguard
add listen-port=13231 mtu=1420 name=wg-mgmt
/ip pool
add name=dhcp_pool0 ranges=10.20.0.100-10.20.0.200
/ip dhcp-server
add address-pool=dhcp_pool0 interface=bridge-lan name=dhcp1
/interface bridge port
add bridge=bridge-lan interface=ether2
/interface wireguard peers
add allowed-address=10.66.0.2/32,0.0.0.0/0 interface=wg-mgmt public-key=\
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ="
/ip address
add address=5.9.10.10/29 interface=ether1-wan network=5.9.10.8
add address=10.20.0.1/24 interface=bridge-lan network=10.20.0.0
add address=10.66.0.1/24 interface=wg-mgmt network=10.66.0.0
/ip dhcp-server network
add address=10.20.0.0/24 gateway=10.20.0.1
/ip dns
set servers=1.1.1.1
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=accept chain=input protocol=udp dst-port=13231
add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes
add action=accept chain=forward connection-state=established,related
/ip firewall nat
add action=masquerade chain=srcnat
add action=dst-nat chain=dstnat dst-port=443 in-interface=ether1-wan protocol=tcp to-addresses=10.20.0.50 to-ports=443
/ip route
add dst-address=0.0.0.0/0 gateway=5.9.10.9
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www-ssl certificate=rest disabled=no
/system identity
set name=chr-edge
