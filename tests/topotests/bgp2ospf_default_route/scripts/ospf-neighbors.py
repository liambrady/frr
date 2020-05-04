from lutil import luCommand

luCommand('r2','vtysh -c "show ip ospf int"','r2-eth2 is up','pass','OSPF Interfaces')
luCommand('r3','vtysh -c "show ip ospf int"','r3-eth1 is up','pass','OSPF Interfaces')
luCommand('r2','vtysh -c "show ip ospf neigh"','Full.*eth','wait','OSPF Full', 60)
luCommand('r3','vtysh -c "show ip ospf neigh"','Full.*eth','wait','OSPF Full', 10)
