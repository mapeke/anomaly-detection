# R-CORE — ядро сети и ЦОД провайдера (RouterOS 7)
/system identity set name=R-CORE
/interface bridge add name=lo
/ip address
add address=10.255.0.2/32 interface=lo
add address=10.0.12.2/30 interface=ether1
add address=10.0.23.1/30 interface=ether2
add address=10.0.0.1/24 interface=ether3
/routing ospf instance add name=ospf1 router-id=10.255.0.2
/routing ospf area add name=backbone instance=ospf1 area-id=0.0.0.0
/routing ospf interface-template add area=backbone networks=10.0.12.0/30,10.0.23.0/30,10.0.0.0/24,10.255.0.2/32
