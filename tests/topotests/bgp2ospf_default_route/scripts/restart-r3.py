from lutil import luCommand

sleepTime = 6

rtr = 'r3'
daemons = ['ospfd', 'zebra']

luCommand(rtr,'ls -alt /etc/frr /var/run/frr','.','none')

for daemon in daemons:
    luCommand(rtr,'cat /var/run/frr/%s.pid'%daemon,'.','pre restart pid')
    luCommand(rtr,'cat /var/run/frr/%s.pid'%daemon,'.','none')
    luCommand(rtr,'kill `cat /var/run/frr/%s.pid`'%daemon,'.','none','kill %s'%daemon)
    luCommand(rtr,'ps `cat /var/run/frr/%s.pid` | wc -l '%daemon,'1','wait','%s killed'%daemon, 10)

luCommand(rtr,'sleep %d; date'%sleepTime, ':', 'pass', 'Slept %d seconds'%sleepTime)

for daemon in reversed(daemons):
    luCommand(rtr,'/usr/lib/frr/%s -d'%daemon,'.','none','restart %s'%daemon)
    luCommand(rtr,'ps `cat /var/run/frr/%s.pid` | wc -l '%daemon,'2','wait','%s restarted'%daemon, 10)
    luCommand(rtr,'cat /var/run/frr/%s.pid'%daemon,'.','none','post restart pid')

    
