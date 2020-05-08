from lutil import luCommand

pfxs = ['8.0.0.0/8', '10.0.3.0/24','0.0.0.0/0','5.6.7.0/26','1.1.1.1/32','2.2.2.2/32','3.3.3.3/32']
for routern in range(1, 4):
    rtr='r{}'.format(routern)
    for pfx in pfxs:
        ret = luCommand(rtr, 'vtysh -c "show ip route"', '0.0.0.0/0', 'wait', 'See %s' % pfx, 60)
#done
