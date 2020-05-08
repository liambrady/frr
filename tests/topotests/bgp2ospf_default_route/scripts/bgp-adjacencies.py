from lutil import luCommand

########################################################################
# ipv4
########################################################################

luCommand('r1','vtysh -c "show bgp ipv4 summary"',' [0-9][0-9]:[0-9]','wait','BGP v4 Adjacencies up',60)
luCommand('r2','vtysh -c "show bgp ipv4 summary"',' [0-9][0-9]:[0-9]','wait','BGP v4 Adjacencies up',10)

########################################################################
# ipv6
########################################################################

luCommand('r1','vtysh -c "show bgp ipv6 summary"',' [0-9][0-9]:[0-9]','wait','BGP v6 Adjacencies up',10)
luCommand('r2','vtysh -c "show bgp ipv6 summary"',' [0-9][0-9]:[0-9]','wait','BGP v6 Adjacencies up',10)
