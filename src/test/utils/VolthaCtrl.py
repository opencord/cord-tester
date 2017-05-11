import requests
import json
import time
from CordTestUtils import log_test as log

class VolthaCtrl(object):

    def __init__(self, host, rest_port = 8881):
        self.host = host
        self.rest_port = rest_port
        self.rest_url = 'http://{}:{}/api/v1'.format(host, rest_port)

    def get_devices(self):
        url = '{}/local/devices'.format(self.rest_url)
        resp = requests.get(url)
        if resp.ok is not True or resp.status_code != 200:
            return None
        return resp.json()

    def enable_device(self, olt_type, olt_mac):
        url = '{}/local/devices'.format(self.rest_url)
        device_config = { 'type' : olt_type, 'mac_address' : olt_mac }
        #pre-provision
        log.info('Pre-provisioning %s with mac %s' %(olt_type, olt_mac))
        resp = requests.post(url, data = json.dumps(device_config))
        if resp.ok is not True or resp.status_code != 200:
            return False
        device_id = resp.json()['id']
        log.info('Enabling device %s' %(device_id))
        enable_url = '{}/{}/enable'.format(url, device_id)
        resp = requests.post(enable_url)
        if resp.ok is not True or resp.status_code != 200:
            return False
        #get operational status
        time.sleep(5)
        log.info('Checking operational status for device %s' %(device_id))
        resp = requests.get('{}/{}'.format(url, device_id))
        if resp.ok is not True or resp.status_code != 200:
            return False
        device_info = resp.json()
        if device_info['oper_status'] != 'ACTIVE' or \
           device_info['admin_state'] != 'ENABLED' or \
           device_info['connect_status'] != 'REACHABLE':
            return False

        return True
