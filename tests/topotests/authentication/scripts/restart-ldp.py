from lutil import luCommand
oneIntf   = 'neighbor.*password 101 '

rtrs = ['r3', 'r5']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'cat /etc/frr/ldpd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'kill `cat ~frr/ldpd.pid`','.','none','kill ldpd')
    luCommand(rtr,'ps `cat ~frr/ldpd.pid` | wc -l ','1','wait','ldpd killed', 5)
    luCommand(rtr,'/usr/lib/frr/ldpd -d','.','none','restart ldpd')
    luCommand(rtr,'ps `cat ~frr/ldpd.pid` | wc -l ','2','wait','ldpd restarted', 5)
    
