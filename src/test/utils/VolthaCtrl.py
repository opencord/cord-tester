import requests
import json
import time
import os
import signal
from CordTestUtils import log_test as log, getstatusoutput
from CordContainer import Container

class VolthaService(object):
    services = ('consul', 'kafka', 'zookeeper', 'registrator', 'fluentd')
    compose_file = 'docker-compose-system-test.yml'
    service_map = {}

    def __init__(self, voltha_loc, controller, interface = 'eth0'):
        if not os.access(voltha_loc, os.F_OK):
            raise Exception('Voltha location %s not found' %voltha_loc)
        compose_file_loc = os.path.join(voltha_loc, 'compose', self.compose_file)
        if not os.access(compose_file_loc, os.F_OK):
            raise Exception('Voltha compose file %s not found' %compose_file_loc)
        self.voltha_loc = voltha_loc
        self.controller = controller
        self.interface = interface
        self.compose_file_loc = compose_file_loc

    def start(self):
        start_cmd = 'docker-compose -f {} up -d {} {} {} {} {}'.format(self.compose_file_loc,
                                                                       *self.services)
        ret = os.system(start_cmd)
        if ret != 0:
            raise Exception('Failed to start voltha services. Failed with code %d' %ret)

        for service in self.services:
            name = 'compose_{}_1'.format(service)
            network = 'compose_default'
            cnt = Container(name, name)
            ip = cnt.ip(network = network)
            if not ip:
                raise Exception('IP not found for container %s' %name)
            print('IP %s for service %s' %(ip, service))
            self.service_map[service] = dict(name = name, network = network, ip = ip)

        #first start chameleon
        chameleon_start_cmd = "cd {} && sh -c '. ./env.sh && \
        nohup python chameleon/main.py -v --consul=localhost:8500 \
        --fluentd={}:24224 --grpc-endpoint=localhost:50555 \
        >/tmp/chameleon.log 2>&1 &'".format(self.voltha_loc,
                                            self.service_map['fluentd']['ip'])
        if not self.service_running('python chameleon/main.py'):
            ret = os.system(chameleon_start_cmd)
            if ret != 0:
                raise Exception('VOLTHA chameleon service not started. Failed with return code %d' %ret)
        else:
            print('Chameleon voltha sevice is already running. Skipped start')

        #now start voltha and ofagent
        voltha_start_cmd = "cd {} && sh -c '. ./env.sh && \
        nohup python voltha/main.py -v --consul=localhost:8500 --kafka={}:9092 -I {} \
        --fluentd={}:24224 --rest-port=8880 --grpc-port=50555 \
        >/tmp/voltha.log 2>&1 &'".format(self.voltha_loc,
                                         self.service_map['kafka']['ip'],
                                         self.interface,
                                         self.service_map['fluentd']['ip'])
        if not self.service_running('python voltha/main.py'):
            ret = os.system(voltha_start_cmd)
            if ret != 0:
                raise Exception('Failed to start VOLTHA. Return code %d' %ret)
        else:
            print('VOLTHA core is already running. Skipped start')

        ofagent_start_cmd = "cd {} && sh -c '. ./env.sh && \
        nohup python ofagent/main.py -v --consul=localhost:8500 \
        --fluentd={}:24224 --controller={}:6653 --grpc-endpoint=localhost:50555 \
        >/tmp/ofagent.log 2>&1 &'".format(self.voltha_loc,
                                          self.service_map['fluentd']['ip'],
                                          self.controller)
        if not self.service_running('python ofagent/main.py'):
            ret = os.system(ofagent_start_cmd)
            if ret != 0:
                raise Exception('VOLTHA ofagent not started. Failed with return code %d' %ret)
        else:
            print('VOLTHA ofagent is already running. Skipped start')

    def service_running(self, pattern):
        st, _ = getstatusoutput('pgrep -f "{}"'.format(pattern))
        return True if st == 0 else False

    def kill_service(self, pattern):
        st, output = getstatusoutput('pgrep -f "{}"'.format(pattern))
        if st == 0 and output:
            pids = output.strip().splitlines()
            for pid in pids:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except:
                    pass

    def stop(self):
        self.kill_service('python voltha/main.py')
        self.kill_service('python ofagent/main.py')
        self.kill_service('python chameleon/main.py')
        service_stop_cmd = 'docker-compose -f {} down'.format(self.compose_file_loc)
        os.system(service_stop_cmd)

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

    def get_operational_status(self, device_id):
        url = '{}/local/devices'.format(self.rest_url)
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

    def check_preprovision_status(self, device_id):
        url = '{}/local/devices'.format(self.rest_url)
        log.info('Check if device %s is in Preprovisioning state'%(device_id))
        resp = requests.get('{}/{}'.format(url, device_id))
        if resp.ok is not True or resp.status_code != 200:
           return False
        device_info = resp.json()
        if device_info['admin_status'] == 'PREPROVISIONED':
           return True
        return False
