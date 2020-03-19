from lutil import luCommand
oneIntf   = 'eth0.*authentication string 101 .*=.*ip rip send'

rtrs = ['r1', 'r2', 'r4']
for rtr in rtrs:
    luCommand(rtr,'vtysh -c "write memory"','.','none','wrote file')
    luCommand(rtr,'cat /etc/frr/ripd.conf',oneIntf,'pass','Auth key encrypted in config')
    luCommand(rtr,'kill `cat ~frr/ripd.pid`','.','none','kill ripd')
    luCommand(rtr,'ps `cat ~frr/ripd.pid` | wc -l ','1','wait','ripd killed', 5)
    luCommand(rtr,'/usr/lib/frr/ripd -d','.','none','restart ripd')
    luCommand(rtr,'ps `cat ~frr/ripd.pid` | wc -l ','2','wait','ripd restarted', 5)
    
