from lutil import luCommand

pfxs = ['0.0.0.0/0', '8.0.0.0/8', '10.0.3.0/24']
for routern in range(1, 4):
    rtr='r{}'.format(routern)
    for pfx in pfxs:
        ret = luCommand(rtr, 'vtysh -c "show ip route"', '0.0.0.0/0', 'wait', 'See %s' % pfx, 10)
#done
