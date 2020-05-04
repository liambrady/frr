from lutil import luCommand

rtr = 'r2'
luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
luCommand(rtr,'cat /var/run/frr/ospfd.pid','.','pre restart pid')
luCommand(rtr,'kill `cat /var/run/frr/bgpd.pid`','.','none','kill bgpd')
luCommand(rtr,'kill `cat /var/run/frr/ospfd.pid`','.','none','kill ospfd')
luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','1','wait','bgpd killed', 10)
luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','1','wait','ospfd killed', 10)
luCommand(rtr,'/usr/lib/frr/bgpd -d','.','none','restart bgpd')
luCommand(rtr,'/usr/lib/frr/ospfd -d','.','none','restart ospfd')
luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','2','wait','bgpd restarted', 10)
luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','2','wait','ospfd restarted', 10)
luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
luCommand(rtr,'cat /var/run/frr/ospfd.pid','.','none','post restart pid')


