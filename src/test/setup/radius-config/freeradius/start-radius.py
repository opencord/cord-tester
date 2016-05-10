#!/usr/bin/env python
import pexpect
import time
child = pexpect.spawn('sh -c radius')
child.expect('Enter PEM pass phrase:')
child.sendline('whatever')
while True:
    time.sleep(3600)
