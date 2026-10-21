# R-BNG — доступ/агрегация абонентов, CGNAT (RouterOS 7)
/system identity set name=R-BNG
/system clock set time-zone-name=UTC
/interface bridge add name=lo
/interface bridge add name=br-subs
/interface bridge port add bridge=br-subs interface=ether2
/interface bridge port add bridge=br-subs interface=ether3
/ip address
add address=10.255.0.3/32 interface=lo
add address=10.0.23.2/30 interface=ether1
add address=100.64.10.1/24 interface=br-subs
/routing ospf instance add name=ospf1 router-id=10.255.0.3
/routing ospf area add name=backbone instance=ospf1 area-id=0.0.0.0
/routing ospf interface-template add area=backbone networks=10.0.23.0/30,100.64.10.0/24,10.255.0.3/32
# Экспорт потоков с абонентского сегмента ДО трансляции адресов (видны адреса абонентов)
/ip traffic-flow set enabled=yes interfaces=br-subs active-flow-timeout=1m inactive-flow-timeout=15s
/ip traffic-flow target add dst-address=10.0.0.100 port=2055 version=9
# В лабораторном стенде CGNAT выключен, чтобы внешние атаки достигали абонентов;
# для проверки NAT: /ip firewall nat add chain=srcnat src-address=100.64.10.0/24 action=src-nat to-addresses=192.0.2.1-192.0.2.14
