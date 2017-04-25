import subprocess
import socket
import fcntl
import struct
import os
import logging

log_test = logging.getLogger('cordTester')
test_consolehandler = logging.StreamHandler()
#test_consolehandler.setFormatter(logging.Formatter("%(levelname)s:%(message)s"))
log_test.addHandler(test_consolehandler)

# we use subprocess as commands.getstatusoutput would be deprecated
def getstatusoutput(cmd):
    command = [ '/bin/sh', '-c', cmd ]
    p = subprocess.Popen(command, stdout = subprocess.PIPE)
    out, _ = p.communicate()
    return p.returncode, out.strip()

def get_ip(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes(iface[:15])))
    except:
        info = None
    s.close()
    if info:
        return '.'.join( [ str(ord(c)) for c in info[20:24] ] )
    return None

def get_mac(iface = None, pad = 4):
    if iface is None:
        iface = os.getenv('TEST_SWITCH', 'ovsbr0')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes(iface[:15])))
    except:
        info = ['0'] * 24
    s.close()
    sep = ''
    if pad == 0:
        sep = ':'
    return '0'*pad + sep.join(['%02x' %ord(char) for char in info[18:24]])

def get_default_gw():
    cmd = "ip route show | grep default | head -1 | awk '{print $3}'"
    cmd_dev = "ip route show | grep default | head -1 | awk '{print $NF}'"
    st, gw = getstatusoutput(cmd)
    st2, gw_device = getstatusoutput(cmd_dev)
    if st != 0:
        gw = None
    if st2 != 0:
        gw_device = None
    return gw, gw_device

def get_controllers():
    controllers = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
    return controllers.split(',')

def get_controller():
    controllers = get_controllers()
    return controllers[0]

def running_on_pod():
    """If we are running on Ciab or inside a physical podd, key file would be set"""
    return True if os.environ.get('SSH_KEY_FILE', None) else False
