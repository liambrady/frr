import pytest
from lutil import luCommand

mk_o='openssl genpkey -algorithm RSA -out ~frr/.ssh/frr'

# can specify "--bits=1024" to certtool for keys smaller than default 3072
mk_c='certtool --generate-privkey --key-type=rsa --null-password --outfile ~frr/.ssh/frr'

cmd='if [ ! -e ~frr/.ssh ] ; then  mkdir ~frr/.ssh ; if which openssl ; then {}; else if which certtool ; then {} ; fi ; fi; chown -R frr.frr ~frr/.ssh ; chmod -R go-rwx ~frr/.ssh ; fi ; ls -al ~frr/.ssh'.format(mk_o, mk_c)

for r in range(0, 8):
    luCommand('r{}'.format(r),cmd,'frr$','pass','key file found')
