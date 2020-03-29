#currently fails if key created after startup
from lutil import luCommand
cmd='mkdir ~frr/.ssh ; openssl genpkey -algorithm RSA -out ~frr/.ssh/frr ; chown -R frr.frr ~frr/.ssh ; chmod -R go-rwx ~frr/.ssh ; ls -al ~frr/.ssh'
for r in range(0, 8):
    luCommand('r{}'.format(r),cmd,'frr$','pass','key file generated')
