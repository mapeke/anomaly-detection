# R-BORDER — граница сети провайдера (RouterOS 7)
/system identity set name=R-BORDER
/interface bridge add name=lo
/ip address
add address=10.255.0.1/32 interface=lo
add address=10.0.12.1/30 interface=ether1
add address=203.0.113.1/24 interface=ether2
add address=198.51.100.1/24 interface=ether3
/routing ospf instance add name=ospf1 router-id=10.255.0.1 redistribute=connected
/routing ospf area add name=backbone instance=ospf1 area-id=0.0.0.0
/routing ospf interface-template add area=backbone networks=10.0.12.0/30,10.255.0.1/32
# Экспорт потоков: NetFlow v9 и IPFIX на коллектор, тайм-ауты кэша 60 с / 15 с
/ip traffic-flow set enabled=yes interfaces=ether2,ether3 active-flow-timeout=1m inactive-flow-timeout=15s cache-entries=128k
/ip traffic-flow target add dst-address=10.0.0.100 port=2055 version=9
/ip traffic-flow target add dst-address=10.0.0.100 port=2055 version=ipfix disabled=yes
