from lutil import luCommand

rtr = 'r1'
luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
luCommand(rtr,'kill `cat /var/run/frr/bgpd.pid`','.','none','kill bgpd')
luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','1','wait','bgpd killed', 10)
luCommand(rtr,'/usr/lib/frr/bgpd -d','.','none','restart bgpd')
luCommand(rtr,'ps `cat /var/run/frr/bgpd.pid` | wc -l ','2','wait','bgpd restarted', 10)
luCommand(rtr,'cat /var/run/frr/bgpd.pid','.','none')
