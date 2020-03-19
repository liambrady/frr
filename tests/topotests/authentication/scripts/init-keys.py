import pytest
from lutil import luCommand

ret = luCommand('r0','vtysh -c "show k s"', 'not included in software build', 'none')
found = luLast()
if ret != False and found != None:
    if len(found.group()):
        luCommand('r0','vtysh -c "show k s"', 'not included in software build', 'pass', 'Skipping test - keycrypt not included in software build')
        pytest.exit('Skipping test - keycrypt not included in software build')

cmd='if [ ! -e ~frr/.ssh ] ; then  mkdir ~frr/.ssh ; openssl genpkey -algorithm RSA -out ~frr/.ssh/frr ; chown -R frr.frr ~frr/.ssh ; chmod -R go-rwx ~frr/.ssh ; fi ; ls -al ~frr/.ssh'
for r in range(0, 8):
    luCommand('r{}'.format(r),cmd,'frr$','pass','key file found')
