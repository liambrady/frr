from lutil import luCommand

rtr = 'r3'

luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')
luCommand(rtr,'cat /var/run/frr/ospfd.pid','.','pre restart pid')
luCommand(rtr,'cat /var/run/frr/ospfd.pid','.','none')
luCommand(rtr,'kill `cat /var/run/frr/ospfd.pid`','.','none','kill ospfd')
luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','1','wait','ospfd killed', 10)
luCommand(rtr,'/usr/lib/frr/ospfd -d','.','none','restart ospfd')
luCommand(rtr,'ps `cat /var/run/frr/ospfd.pid` | wc -l ','2','wait','ospfd restarted', 10)
luCommand(rtr,'cat /var/run/frr/ospfd.pid','.','none','post restart pid')

    
