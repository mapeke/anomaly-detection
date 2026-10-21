# R-CORE — ядро сети и ЦОД провайдера (RouterOS 7)
# ether3 -> коммутатор ЦОД: ISP-SRV 10.0.0.53 и облако GNS3 (Windows-хост с коллектором 10.0.0.100)
/system identity set name=R-CORE
/system clock set time-zone-name=UTC
/interface bridge add name=lo
/ip address
add address=10.255.0.2/32 interface=lo
add address=10.0.12.2/30 interface=ether1
add address=10.0.23.1/30 interface=ether2
add address=10.0.0.1/24 interface=ether3
/routing ospf instance add name=ospf1 router-id=10.255.0.2
/routing ospf area add name=backbone instance=ospf1 area-id=0.0.0.0
/routing ospf interface-template add area=backbone networks=10.0.12.0/30,10.0.23.0/30,10.0.0.0/24,10.255.0.2/32
# Изоляция хоста-коллектора: к 10.0.0.100 пропускается только NetFlow от маршрутизаторов,
# весь остальной трафик стенда (в том числе атаки) к Windows-хосту отбрасывается
/ip firewall filter
add chain=forward dst-address=10.0.0.100 protocol=udp dst-port=2055 src-address=10.0.12.1 action=accept comment="NetFlow R-BORDER"
add chain=forward dst-address=10.0.0.100 protocol=udp dst-port=2055 src-address=10.0.23.2 action=accept comment="NetFlow R-BNG"
add chain=forward dst-address=10.0.0.100 action=drop comment="isolate collector host"
add chain=forward src-address=10.0.0.100 connection-state=new action=drop comment="host cannot initiate into lab"
