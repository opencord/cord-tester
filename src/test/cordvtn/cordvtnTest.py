#
# Copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import unittest
import os,sys
import keystoneclient.v2_0.client as ksclient
import keystoneclient.apiclient.exceptions
import neutronclient.v2_0.client as nclient
import neutronclient.common.exceptions
import novaclient.v1_1.client as novaclient
from novaclient import client as nova_client
from multiprocessing import Pool
from neutronclient.v2_0 import client as neutron_client
import neutronclient.v2_0.client as neutronclient
from nose.tools import assert_equal
from CordTestUtils import get_mac, log_test
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl
from CordLogger import CordLogger
from TestManifest import TestManifest
from OnosFlowCtrl import OnosFlowCtrl
from scapy.all import *
from credentials import *
from VSGAccess import VSGAccess
from SSHTestAgent import SSHTestAgent
import requests
import time
import py_compile
import json

PROTO_NAME_TCP = 'tcp'
PROTO_NAME_ICMP = 'icmp'
IPv4 = 'IPv4'

OS_USERNAME = 'admin'
OS_PASSWORD = 'VeryLongKeystoneAdminPassword'
OS_TENANT = 'admin'
OS_AUTH_URL = 'https://keystone.cord.lab:5000/v2.0'
OS_SERVICE_ENDPOINT = 'https://keystone.cord.lab:5000/v2.0/'
VM_BOOT_TIMEOUT = 100
VM_DELETE_TIMEOUT = 100


#VM SSH CREDENTIALS
VM_USERNAME = 'ubuntu'
VM_PASSWORD = 'ubuntu'

TENANT_PREFIX = 'test-'
VM_PREFIX = 'test-'
NETWORK_PREFIX = 'test-'
CIDR_PREFIX = '192.168'

class vtn_validation_utils:

    endpoint = '172.17.0.5'
    version = ''
    vtn_app = 'org.opencord.vtn'

    def __init__(self, version):
        self.version = version
        self.manifest = None
        self.vtn_enabled = False
        manifest = os.getenv('MANIFEST', None)
        if manifest:
            self.manifest = TestManifest(manifest = manifest)
            self.endpoint = self.manifest.onos_ip
            self.vtn_enabled = self.manifest.synchronizer == 'vtn'

        self.app_ctrl = OnosCtrl(self.vtn_app, controller = self.endpoint)

    def getDevices(self):
        return OnosCtrl.get_devices(controller = self.endpoint)

    def getLinks(self):
        return OnosCtrl.get_links(controller = self.endpoint)

    def getDevicePorts(self, switch_id):
        return OnosCtrl.get_ports_device(switch_id, controller = self.endpoint)

    def activateVTNApp(self):
        return self.app_ctrl.activate()

    def deactivateVTNApp(self):
        return self.app_ctrl.deactivate()

class cordvtn_exchange(CordLogger):

    app_cordvtn = 'org.opencord.vtn'
    test_path = os.path.dirname(os.path.realpath(__file__))
    cordvtn_dir = os.path.join(test_path, '..', 'setup')
    cordvtn_conf_file = os.path.join(test_path, '..', '../cordvtn/network_cfg.json')
    head_node_user = 'vagrant'
    head_node_pass = 'vagrant'
    head_node = os.getenv('HEAD_NODE', 'prod')
    head_node_ip = '10.1.0.1'
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node


    @classmethod
    def setUpClass(cls):
        ''' Activate the cordvtn app'''
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.app_cordvtn)
        status, _ = cls.onos_ctrl.activate()
        #assert_equal(status, True)
        time.sleep(3)
        cls.cordvtn_setup()

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the cord vtn app'''
        #cls.onos_ctrl.deactivate()
        #cls.cord_vtn_cleanup()

    @classmethod
    def cordvtn_setup(cls):
        pass

    @classmethod
    def cord_vtn_cleanup(cls):
        ##reset the ONOS port configuration back to default
        pass

    @classmethod
    def onos_load_config(cls, cordvtn_conf_file):
        status, code = OnosCtrl.config(cordvtn_conf_file)
        if status is False:
            log_test.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

    def get_neutron_credentials(self):
        n = {}
        n['username'] = os.environ['OS_USERNAME']
        n['password'] = os.environ['OS_PASSWORD']
        n['auth_url'] = os.environ['OS_AUTH_URL']
        n['tenant_name'] = os.environ['OS_TENANT_NAME']
        n['ca_cert'] = os.environ['REQUESTS_CA_BUNDLE']
        return n

    @classmethod
    def get_compute_nodes(cls):
        credentials = get_nova_credentials_v2()
        novaclient = nova_client.Client('2', **credentials)
        print novaclient.hypervisors.list()
        return novaclient.hypervisors.list()

    def create_network(i):
        neutron_credentials = get_neutron_credentials()
        neutron = neutron_client.Client(**neutron_credentials)
        json = {'network': {'name': 'network-' + str(i),
                            'admin_state_up': True}}
        while True:
           try:
              net = neutron.create_network(body=json)
              print '\nnetwork-' + str(i) + ' created'
              return net
           except Exception as e:
              print e
              continue

    def create_tenant(tenant_name):
        new_tenant = keystone.tenants.create(tenant_name=tenant_name,
                     description="CORD Tenant \
                     created",
                     enabled=True)
        tenant_id = new_tenant.id
        tenant_status = True
        user_data = []
        for j in range(2):
            j += 1
            user_name = tenant_name + '-user-' + str(j)
            user_data.append(create_user(user_name, tenant_id))

        print " Tenant and User Created"

        tenant_data = {'tenant_name': tenant_name,
                       'tenant_id': tenant_id,
                       'status': tenant_status}
        return tenant_data

    def create_user(user_name, tenant_id):
        new_user = keystone.users.create(name=user_name,
                                         password="ubuntu",
                                         tenant_id=tenant_id)
        print('   - Created User %s' % user_name)
        keystone.roles.add_user_role(new_user, member_role, tenant_id)
        if assign_admin:
           admin_user = keystone.users.find(name='admin')
           admin_role = keystone.roles.find(name='admin')
           keystone.roles.add_user_role(admin_user, admin_role, tenant_id)
        user_data = {'name': new_user.name,
                     'id': new_user.id}
        return user_data

    def create_port( router_id, network_id):
        credentials = get_credentials()
        neutron = client.Client(**credentials)
        router = neutron.show_router(router_id)

        value = {'port':{
        'admin_state_up':True,
        'device_id': router_id,
        'name': 'port1',
        'network_id':network_id,
        }}
        response = neutron.create_port(body=value)

    def router_create(self, name):
        external_network = None
        for network in self.neutron.list_networks()["networks"]:
            if network.get("router:external"):
                external_network = network
                break

        if not external_network:
            raise Exception("Alarm! Can not to find external network")

        gw_info = {
            "network_id": external_network["id"],
            "enable_snat": True
        }
        router_info = {
            "router": {
                "name": name,
                "external_gateway_info": gw_info,
                "tenant_id": self.tenant_id
            }
        }
        router = self.neutron.router_create(router_info)['router']
        return router

    def delete_tenant(tenant_name):
        tenant = keystone.tenants.find(name=tenant_name)
        for j in range(2):
            j += 1
            user_name = tenant_name + '-user-' + str(j)
            delete_user(user_name, tenant.id)
        tenant.delete()
        print('   - Deleted Tenant %s ' % tenant_name)
        return True

    def delete_user(user_name, tenant_id):
        user = keystone.users.find(name=user_name)
        user.delete()

        print('   - Deleted User %s' % user_name)
        return True

    def set_environment(tenants_num=0, networks_per_tenant=1, vms_per_network=2):
        octet = 115
        vm_inc = 11
        image = nova_connection.images.get(IMAGE_ID)
        flavor = nova_connection.flavors.get(FLAVOR_ID)

        admin_user_id = keystone_connection.users.find(name=OS_USERNAME).id
        member_role_id = keystone_connection.roles.find(name='Member').id
        for num_tenant in range(1, tenants_num+1):
            tenant = keystone_connection.tenants.create('%stenant%s' % (TENANT_PREFIX, num_tenant))
            keystone_connection.roles.add_user_role(admin_user_id, member_role_id, tenant=tenant.id)
            for num_network in range(networks_per_tenant):
                network_json = {'name': '%snet%s' % (NETWORK_PREFIX, num_tenant*10+num_network),
                                'admin_state_up': True,
                                'tenant_id': tenant.id}
                network = neutron_connection.create_network({'network': network_json})
                subnet_json = {'name': '%ssubnet%s' % (NETWORK_PREFIX, num_tenant*10+num_network),
                               'network_id': network['network']['id'],
                               'tenant_id': tenant.id,
                               'enable_dhcp': True,
                               'cidr': '%s.%s.0/24' % (CIDR_PREFIX, octet), 'ip_version': 4}
                octet += 1
                subnet = neutron_connection.create_subnet({'subnet': subnet_json})
                router_json = {'name': '%srouter%s' % (NETWORK_PREFIX, num_tenant*10+num_network),
                               'tenant_id': tenant.id}
                router = neutron_connection.router_create({'router': router_json})
                port = neutron_connection.add_interface_router(router['router']['id'], {'subnet_id': subnet['subnet']['id']})
                for num_vm in range(vms_per_network):
                    tenant_nova_connection = novacli.Client(OS_USERNAME, OS_PASSWORD, tenant.name, OS_AUTH_URL)
                    m = tenant_nova_connection.servers.create('%svm%s' % (VM_PREFIX, vm_inc), image, flavor, nics=[{'net-id': network['network']['id']}, {'net-id': MGMT_NET}])
                    vm_inc += 1

    def verify_neutron_crud():
        x = os.system("neutron_test.sh")
        return x

    def list_floatingips( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_floatingips(**kwargs)['floatingips']

    def list_security_groups( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_security_groups(**kwargs)['security_groups']

    def list_subnets( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_subnets(**kwargs)['subnets']

    def list_networks( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_networks(**kwargs)['networks']

    def list_ports( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_ports(**kwargs)['ports']

    def list_routers( **kwargs):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        return neutron.list_routers(**kwargs)['routers']

    def update_floatingip( fip, port_id=None):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.update_floatingip(fip, {"floatingip":
                                              {"port_id": port_id}})

    def update_subnet( subnet_id, **subnet_params):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.update_subnet(subnet_id, {'subnet': subnet_params})

    def update_router( router_id, **router_params):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.update_router(router_id, {'router': router_params})

    def router_gateway_set( router_id, external_gateway):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.update_router(
        router_id, {'router': {'external_gateway_info':
                               {'network_id': external_gateway}}})

    def router_gateway_clear( router_id):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.update_router(
        router_id, {'router': {'external_gateway_info': None}})

    def router_add_interface( router_id, subnet_id):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.add_interface_router(router_id, {'subnet_id': subnet_id})

    def router_rem_interface( router_id, subnet_id):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        neutron.remove_interface_router(
        router_id, {'subnet_id': subnet_id})

    def create_floatingip( **floatingip_params):
        creds = get_neutron_credentials()
        neutron = client.Client(**creds)
        response = neutron.create_floatingip(
        {'floatingip': floatingip_params})
        if 'floatingip' in response and 'id' in response['floatingip']:
           return response['floatingip']['id']

    def make_iperf_pair(server, client, **kwargs):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(MissingHostKeyPolicy())

        ssh.connect(server, username=VM_USERNAME, password=VM_PASSWORD)
        ssh.exec_command('/usr/local/bin/iperf3 -s -D')

        ssh.connect(client, username=VM_USERNAME, password=VM_PASSWORD)
        stdin, stdout, stderr = ssh.exec_command('/usr/local/bin/iperf3 -c %s -J' % server)

        rawdata = stdout.read()
        data = json.loads(rawdata.translate(None,'\t').translate(None,'\n'))

        return data

    def connect_ssh(os_ip, private_key_file=None, user='ubuntu'):
        key = ssh.RSAKey.from_private_key_file(private_key_file)
        client = ssh.SSHClient()
        client.set_missing_host_key_policy(ssh.WarningPolicy())
        client.connect(ip, username=user, pkey=key, timeout=5)
        return client

    def validate_vtn_flows(switch):
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        device_id = 'of:{}'.format(get_mac(switch))
        ctlr = self.ctlr_ip.split(',')[0]
        flow = OnosFlowCtrl(deviceId = device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethType = '0x800',
                            ipSrc = ('IPV4_SRC', ingress_map['ip']+'/32'),
                            ipDst = ('IPV4_DST', egress_map['ip']+'/32'),
                            controller = ctlr
                            )
        flow_id = flow.findFlow(device_id, IN_PORT = ('port', ingress),
                                ETH_TYPE = ('ethType','0x800'), IPV4_SRC = ('ip', ingress_map['ip']+'/32'),
                                IPV4_DST = ('ip', egress_map['ip']+'/32'))
        if flow_id:
           return True

    def cliEnter(self):
        retries = 0
        while retries < 3:
            self.cli = OnosCliDriver(connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()


    def cordvtn_config_load(self, config = None):
        if config:
           for k in config.keys():
               if cordvtn_config.has_key(k):
                  cordvtn_config[k] = config[k]
        self.onos_load_config(self.cordvtn_dict)

    def search_value(self, d, pat):
        match = False
        for k, v in d.items():
            if isinstance(v, dict):
               match = self.search_value(v, pat)
               if match is True:
                  break
            elif type(v) is list:
                 for i in range(len(v)):
                    if type(v[i]) is dict:
                       match = self.search_value(v[i], pat)
                       if match is True:
                          break
                    else:
                       if v[i] == pat:
                          match = True
                          return match
            elif v == pat:
                 match = True
                 return match
        if match is True:
           print"Network search is successful"
        return match

    def get_key_value(self, d, key = None, value = None,):
        match = False
        ret_k = ""
        ret_v = ""
        if type(d) is not dict:
           if type(d) is not list:
              match = 'NOT_FOUND'
              return [match, ret_k, ret_v]
           else:
              for i in range(len(d)):
                  if type(d[i]) is dict:
                     match,ret_k,ret_v = self.get_key_value(d[i], key, value)
                     if match is True:
                        print "Network creation is successful"
                        break
        else:
           for k, v in d.items():
              if isinstance(v, dict):
                 match,ret_k,ret_v = self.get_key_value(v, key, value)
                 if match is True:
                    break
              elif type(v) is list:
                   for i in range(len(v)):
                      if type(v[i]) is dict:
                         match,ret_k,ret_v = self.get_key_value(v[i], key, value)
                         if match is True:
                            break
                      else:
                         if key:
                            if k == key:
                               match = True
                               return [match, key, v]
                         elif value:
                              if v == value:
                                 match = True
                                 return [match, k, value]
              else:
                  if key:
                     if k == key:
                        match = True
                        return [match, key, v]
                     elif value:
                        if v == value:
                           match = True
                           return [match, k, value]
        if match == False:
           match = 'NOT_FOUND'
        return [match, ret_k, ret_v]

    def neutron_network_creation_and_validation(self, net_name):
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": net_name,"admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        networks = neutron.list_networks(name=net_name)
        data = networks
        return self.search_value(data, net_name)

    def neutron_network_deletion(self, net_name):
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        networks = neutron.list_networks(name=net_name)
        net_id = self.get_key_value(d=networks, key = 'id')
        net = neutron.delete_network(net_id[2])
        return self.get_key_value(d=networks, value = net_name)

    def temp_neutron_subnet_creation_and_validation_v1(self,net_name,sub_cird, sub_net_start = "172.27.0.2", sub_net_end = "172.27.0.200"):
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        networks = neutron.list_networks(name=net_name)
        net_id = self.get_key_value(d=networks, key = 'id')
        cidr = sub_cird
        body_subnet_example = {"subnet":{"network_id": net_id[2],"ip_version":4, "cidr":str(cidr),  "allocation_pools": [{"start": "172.27.0.20", "end": "172.27.0.21"}]}}
        neutron_sub = neutron.create_subnet(body_subnet_example)
        networks = neutron.list_networks(name=net_name)
        return self.get_key_value(d=networks, key = 'subnets')

    def neutron_subnet_creation_and_validation(self,net_name,sub_cird):
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        networks = neutron.list_networks(name=net_name)
        net_id = self.get_key_value(d=networks, key = 'id')
        if sub_cird[0] == 'management':
           cidr = sub_cird[1]
           body_subnet_example = {"subnet":{"network_id": net_id[2],"ip_version":4, "cidr":str(cidr),  "allocation_pools": [{"start": sub_cird[2], "end": sub_cird[3]}]}}
        elif sub_cird[0] == 'public':
           cidr = sub_cird[1]
           gate_way = sub_cird[2]
           body_subnet_example = {"subnet":{"network_id": net_id[2],"ip_version":4, "cidr":str(cidr), "gateway_ip":str(gate_way)}}
        elif sub_cird[0] == 'private':
           cidr = sub_cird[1]
           gate_way = sub_cird[2]
           body_subnet_example = {"subnet":{"network_id": net_id[2],"ip_version":4, "cidr":str(cidr), "gateway_ip":str(gate_way)}}

        neutron_sub = neutron.create_subnet(body_subnet_example)
        networks = neutron.list_networks(name=net_name)
        return self.get_key_value(d=networks, key = 'subnets')

    def sub_network_type_post_to_onos(self,net_name,sub_net_type):

        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        networks = neutron.list_networks(name=net_name)
        net_id = self.get_key_value(d=networks, key = 'id')
        vtn_util = vtn_validation_utils('')

        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')
        network_data = {"ServiceNetwork":{"id": net_id[2],"type":sub_net_type, "providerNetworks":[]}}
        json_network_type_data = json.dumps(network_data)
        resp = requests.post(url=url, auth=auth, data =json_network_type_data)
        return resp

    def service_dependency_on_network_post_to_onos(self,service_network_name,provider_network_name,service_network_type ='private'):

        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        service_network = neutron.list_networks(name=service_network_name)
        service_net_id = self.get_key_value(d=service_network, key = 'id')
        provider_network = neutron.list_networks(name=provider_network_name)
        provider_net_id = self.get_key_value(d=provider_network, key = 'id')
        vtn_util = vtn_validation_utils('')

        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')
        network_data = {"ServiceNetwork":{"id": service_net_id[2],"type":service_network_type, "providerNetworks":[{"bidirectional": 'true', "id": provider_net_id[2]}]}}
        json_network_type_data = json.dumps(network_data)
        resp = requests.post(url=url, auth=auth, data =json_network_type_data)
        return resp

    def nova_instance_creation_and_validation(self,net_name,nova_obj,instance_name,image_name, flavor_id):
        print nova_obj.images.list()
        image = nova_obj.images.find(name=image_name)
        flavor = nova_obj.flavors.find(name=flavor_id)

        nics_list = ""
        if len(net_name) == 2:
            network_1 = nova_obj.networks.find(label=net_name[0])
            network_2 = nova_obj.networks.find(label=net_name[1])
            print network_1.id
            print network_2.id
            nics_list = [{'net-id':network_1.id},{'net-id':network_2.id}]
        else:
            network_1 = nova_obj.networks.find(label=net_name)
            print network_1.id
            nics_list = [{'net-id':network_1.id}]

        server = nova_obj.servers.create(name = instance_name,
                                         image = image.id,
                                         flavor = flavor.id,
                                         nics = nics_list,
                                         userdata = "#cloud-config \n password: ubuntu \n chpasswd: { expire: False }\n ssh_pwauth: True")
                                 #        key_name = 'id_rsa')
        server_details =  nova_obj.servers.find(id=server.id)
        print('Server is launched and status is %s' %server_details.status)
        if server_details.status == 'BUILD':
           time.sleep(120)
        server_details =  nova_obj.servers.find(id=server.id)
        print('After delay server status is %s state'%server_details.status)
        if server_details.status == 'ERROR':
           print('Server status is still in %s state'%server_details.status)
        server_boot_up_log = nova_obj.servers.get_console_output(server.id)
        print 'Server boot Up console log \n%s'%server_boot_up_log
        return server_details

    def create_net_subnet_nova_instance(self,net_name, subnet_name, instance_vm_details,management_type):
        result = self.neutron_network_creation_and_validation(net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(net_name,subnet_name)# sub_net_start = subnet_name[2], sub_net_end =subnet_name[3])
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(net_name, management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(net_name,nova,instance_vm_details[0],instance_vm_details[1],instance_vm_details[2])
        assert_equal(new_instance_details.status, 'ACTIVE')
        return [nova, new_instance_details]

    def nova_instance_tenants_access_check(self, target_tenants_details, compute_details = None, source_tenants_details = None , check_type = 'Ping_from_compute'):
        source_tenant_ip = ''
        target_tenant_ip = ''
        cmd = ''
        status = ''
        output = ''

        ## TO DO New instance is not getting subnet ip, hence checking only mysite-vsg1 vm from compute node
        if compute_details is None:
           compute_ip = '10.1.0.17'
        else:
           compute_ip = compute_details.ip

        ## TO DO New instance is not getting subnet ip, hence checking only mysite-vsg1 vm from compute node
        if target_tenants_details == {}:
           target_tenants_details = '10.1.0.1'

        ## TO DO New instance is not getting subnet ip, hence checking only mysite-vsg1 vm from compute node
        if source_tenants_details is not None:
           if source_tenants_details == {}:
              source_tenants_details = '10.1.0.1'

        if check_type == "Ping_from_compute":
           cmd2 = "ping -c 3 {0}".format(target_tenants_details)
           ssh_agent = SSHTestAgent(host = compute_ip)
           status, output = ssh_agent.run_cmd(cmd2, timeout = 5)
           print output

        if source_tenants_details is not None:
           if check_type == "Ping_from_source_tenant":
              cmd = "ping -c 3 {0}".format(target_tenants_details)
              ssh_cmd = 'ssh {} {}'.format(source_tenants_details, cmd)
              print 'Executing ssh command on compute node %s'%ssh_cmd
              ssh_agent = SSHTestAgent(host = compute_ip)
              status, output = ssh_agent.run_cmd(ssh_cmd, timeout = 5)
              print output

        if check_type == "Ping_to_external":
           cmd = "ping -c 3 google.com"
           ssh_cmd = 'ssh {} {}'.format(target_tenants_details, cmd)
           ssh_agent = SSHTestAgent(host = compute_ip)
           status, output = ssh_agent.run_cmd(ssh_cmd, timeout = 5)
           print output

        if status == True and output:
           print "Ping is successful"
           output = output.strip()
        elif status == False:
           print "Ping is not successful"
           output = None
        return [status, output]


    def nova_instance_deletion(self, nova_obj, server_details):
        results_nova_instance_deletion=nova_obj.servers.delete(server_details.id)
        if results_nova_instance_deletion == None:
           print"Nova instance is deleted"
        else:
           print"Nova instance is not deleted"
        return results_nova_instance_deletion

    def test_cordvtn_neutron_network_creation_and_validation_on_head_node_with_neutron_service(self):
        """
        Algo:
        0. Create vtn_test_1_net.
        1. Do GET Rest API and validate creation of network.
        2. Validate network on neutron openstack.
        """
        result = self.neutron_network_creation_and_validation('vtn_test_1_net')
        if result is True:
           self.neutron_network_deletion('vtn_test_1_net')
        assert_equal(result, True)

    def test_cordvtn_neutron_network_creation_and_validation_on_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "vtn_test_2_net","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "vtn_test_2_net")
        self.neutron_network_deletion('vtn_test_2_net')
        assert_equal(result, True)

    def test_cordvtn_with_neutron_network_deletion_recreation_and_validation_on_head_node_with_neutron_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        result = self.neutron_network_creation_and_validation('vtn_test_3_net')
        if result is True:
           self.neutron_network_deletion('vtn_test_3_net')
        assert_equal(result, True)
        result_again = self.neutron_network_creation_and_validation('vtn_test_3_net')
        if result_again is True:
           self.neutron_network_deletion('vtn_test_3_net')
        assert_equal(result, True)

    def test_cordvtn_with_neutron_network_deletion_recreation_and_validation_on_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "vtn_test_4_net","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "vtn_test_4_net")
        assert_equal(result, True)
        self.neutron_network_deletion('vtn_test_4_net')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "vtn_test_4_net")
        assert_equal(result, False)
        net = neutron.create_network(body=body_example)
        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "vtn_test_4_net")
        self.neutron_network_deletion('vtn_test_4_net')
        assert_equal(result, True)

    def test_cordvtn_with_neutron_management_network_creation_and_validation_on_head_node_with_neutron_service(self):
        test_net_name = 'vtn_test_5_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        result = self.neutron_network_creation_and_validation('vtn_test_5_net_management')
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        if sub_result[0] is True:
           self.neutron_network_deletion('vtn_test_5_net_management')
        assert_equal(sub_result[0], True)

    def test_cordvtn_with_neutron_management_network_creation_and_validation_on_onos(self):
        self.neutron_network_creation_and_validation('vtn_test_6_net_management')
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        networks = neutron.list_networks(name='vtn_test_6_net_management')
        net_id = self.get_key_value(d=networks, key = 'id')
        cidr = "172.27.0.0/24"
        body_subnet_example = {"subnet":{"network_id": net_id[2],"ip_version":4, "cidr":str(cidr),  "allocation_pools": [{"start": "172.27.0.20", "end": "172.27.0.21"}]}}
        neutron_sub = neutron.create_subnet(body_subnet_example)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == 'vtn_test_6_net_management':
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    log_test.info('Sub network is not successful')
                    self.neutron_network_deletion('vtn_test_6_net_management')
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == cidr:
                    log_test.info('Sub network is successful')
                    self.neutron_network_deletion('vtn_test_6_net_management')
                    assert_equal(sub_net_id[0], True)
                    break

    def test_cordvtn_neutron_management_network_creation_and_post_network_type_management_local_to_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Pushed the network type as management local to onos
        5. Verified that onos is having under management network
        """
        test_net_name = 'vtn_test_7_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == test_net_name:
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    log_test.info('Sub network is not successful')
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == test_sub_net_cidr[1]:
                    log_test.info('Sub network is successful')
                    assert_equal(sub_net_id[0], True)
                    break

        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        print("Response from onos to change network service type as management local = %s" %net_type_post.text)
        net_type_json = json.loads(net_type_post.text)
        self.neutron_network_deletion(test_net_name)
        assert_equal(net_type_json['message'], 'null already exists')

    def test_cordvtn_with_management_network_creation_launching_nova_instance_and_validation_on_head_node_with_nova_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        """
        test_net_name = 'vtn_test_8_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_8_nova_instance_management_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        self.neutron_network_deletion(test_net_name)
        self.nova_instance_deletion(nova, new_instance_details)
        assert_equal(new_instance_details.status, 'ACTIVE')

    def test_cordvtn_with_public_network_creation_and_validation_on_head_node_with_neutron_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork who ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        test_net_name = 'vtn_test_9_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        if sub_result[0] is True:
           self.neutron_network_deletion(test_net_name)
        assert_equal(sub_result[0], True)

    def test_cordvtn_with_public_network_creation_and_validation_on_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whoes ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        """
        test_net_name = 'vtn_test_10_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26", '10.6.1.193']
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == test_net_name:
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    print('Sub network is not successful')
                    self.neutron_network_deletion(test_net_name)
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == test_sub_net_cidr[1]:
                    print('Sub network is successful')
                    self.neutron_network_deletion(test_net_name)
                    assert_equal(sub_net_id[0], True)
                    break

    def test_cordvtn_with_public_network_creation_and_post_network_type_as_public_to_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Pushed the network type as management local to onos
        5. Verified that onos is having under management network
        """
        test_net_name = 'vtn_test_11_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26", '10.6.1.193']
        test_management_type = "public"
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == test_net_name:
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    log_test.info('Sub network is not successful')
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == test_sub_net_cidr[1]:
                    log_test.info('Sub network is successful')
                    assert_equal(sub_net_id[0], True)
                    break

        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        print("Response from onos to change network service type as management local = %s" %net_type_post.text)
        net_type_json = json.loads(net_type_post.text)

        self.neutron_network_deletion(test_net_name)
        assert_equal(net_type_json['message'], 'null already exists')

    def test_cordvtn_public_network_creation_with_launching_nova_instance_and_validation_on_head_node_with_nova_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under public network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under public network
        5. Validate new nova instance is created on nova service
        """
        test_net_name = 'vtn_test_12_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        instance_vm_name = 'vtn_test_12_nova_instance_public_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        self.neutron_network_deletion(test_net_name)
        self.nova_instance_deletion(nova, new_instance_details)
        assert_equal(new_instance_details.status, 'ACTIVE')

    def test_cordvtn_with_private_network_creation_and_validation_on_head_node_with_neutron_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork who ip is under private network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        test_net_name = 'vtn_test_13_net_private'
        test_sub_net_cidr = ["private","10.160.160.160/24",'10.160.160.1']
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        if sub_result[0] is True:
           self.neutron_network_deletion(test_net_name)
        assert_equal(sub_result[0], True)

    def test_cordvtn_with_private_network_creation_and_validation_on_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whoes ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        """
        test_net_name = 'vtn_test_14_net_private'
        test_sub_net_cidr = ["private","10.160.160.160/24", '10.160.160.1']
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == test_net_name:
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    print('Sub network is not successful')
                    self.neutron_network_deletion(test_net_name)
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == '10.160.160.0/24':
                 #elif sub_net_id[2] == test_sub_net_cidr[1]:
                    print('Sub network is successful')
                    self.neutron_network_deletion(test_net_name)
                    assert_equal(sub_net_id[0], True)
                    break

    def test_cordvtn_with_private_network_creation_and_post_network_type_as_private_to_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Pushed the network type as management local to onos
        5. Verified that onos is having under management network
        """
        test_net_name = 'vtn_test_15_net_private'
        test_sub_net_cidr = ["private","192.168.160.160/24", '192.168.160.1']
        test_management_type = "private"
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)

        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        for i in range(len(data['ServiceNetworks'])):
              if data['ServiceNetworks'][i]['name'] == test_net_name:
                 sub_net_id = self.get_key_value(d=data['ServiceNetworks'][i], key = 'subnet')
                 if sub_net_id[2] == " ":
                    log_test.info('Sub network is not successful')
                    assert_equal(False, True)
                    break
                 elif sub_net_id[2] == "192.168.160.0/24":
                    log_test.info('Sub network is successful')
                    assert_equal(sub_net_id[0], True)
                    break

        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        print("Response from onos to change network service type as management local = %s" %net_type_post.text)
        net_type_json = json.loads(net_type_post.text)

        self.neutron_network_deletion(test_net_name)
        assert_equal(net_type_json['message'], 'null already exists')

    def test_cordvtn_with_private_network_creation_launching_nova_instance_and_validating_on_head_node_with_nova_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under private network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under private network
        5. Validate new nova instance is created on nova service
        """
        test_net_name = 'vtn_test_16_net_private'
        test_sub_net_cidr = ["private","192.168.160.160/24", '192.168.160.1']
        instance_vm_name = 'vtn_test_16_nova_instance_private_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        self.neutron_network_deletion(test_net_name)
        self.nova_instance_deletion(nova, new_instance_details)
        assert_equal(new_instance_details.status, 'ACTIVE')

    def test_cordvtn_management_network_instance_and_validate_connectivity_from_host_machine_or_compute_node(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_17_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_17_nova_instance_management_net'
        #image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, True)

    def test_cordvtn_for_management_network_instance_and_validate_connectivity_to_external_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_18_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_18_nova_instance_management_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'], check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_with_management_network_creating_two_instances_and_validate_connectivity_between_two(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create first nova instance under management network
        5. Validate first nova instance is created on nova service
        6. Create second nova instance under management network
        7. Validate second nova instance is created on nova service
        8. Now try to ping from one nova instance to other instance, should not success
        """
        test_net_name = 'vtn_test_19_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.2", "172.27.0.200"]
        test_management_type = "management_local"
        first_instance_vm_name = 'vtn_test_19_nova_1st_instance_management_net'
        second_instance_vm_name = 'vtn_test_19_nova_2nd_instance_management_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        first_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,first_instance_vm_name,image_name,flavor_id)
        second_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,second_instance_vm_name,image_name,flavor_id)
        assert_equal(first_instance_details.status, 'ACTIVE')
        assert_equal(second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print first_nova_instance_details.addresses
        print second_nova_instance_details.addresses
        address_1st_instance = first_nova_instance_details.addresses
        address_2nd_instance = second_nova_instance_details.addresses
        print 'Nova 1st instance management ip = %s'%(address_1st_instance[test_net_name][0]['addr'])
        print 'Nova 2nd instance management ip = %s'%(address_2nd_instance[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_net_name][0]['addr'],source_tenants_details =address_2nd_instance[test_net_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, first_nova_instance_details)
        self.nova_instance_deletion(nova, second_nova_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_two_management_network_instances_and_validate_connectivity_between_two_networks_via_management_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        """
        test_netA_name = 'vtn_test_20_netA_management'
        test_sub_netA_cidr = ["management","172.27.0.0/24","172.27.0.2", "172.27.0.200"]
        netA_instance_vm_name = 'vtn_test_20_nova_netA_instance_management_net'
        test_netB_name = 'vtn_test_20_netB_management'
        test_sub_netB_cidr = ["management","172.28.0.0/24","172.28.0.2", "172.28.0.200"]
        netB_instance_vm_name = 'vtn_test_20_nova_netB_instance_management_net'
        test_management_type = "management_local"
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        netA_instance_vm_details = [netA_instance_vm_name, image_name, flavor_id]
        netB_instance_vm_details = [netB_instance_vm_name, image_name, flavor_id]

        nova_netA, nova_instance_details_netA = self.create_net_subnet_nova_instance(test_netA_name, test_sub_netA_cidr, netA_instance_vm_details, test_management_type)
        nova_netB, nova_instance_details_netB = self.create_net_subnet_nova_instance(test_netB_name, test_sub_netB_cidr, netB_instance_vm_details, test_management_type)

        assert_equal(nova_instance_details_netA.status, 'ACTIVE')
        assert_equal(nova_instance_details_netB.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print nova_instance_details_netA.addresses
        print nova_instance_details_netB.addresses
        address_1st_instance = nova_instance_details_netA.addresses
        address_2nd_instance = nova_instance_details_netB.addresses
        print 'Nova 1st instance management ip = %s'%(address_1st_instance[test_netA_name][0]['addr'])
        print 'Nova 2nd instance management ip = %s'%(address_2nd_instance[test_netB_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_netA_name][0]['addr'],source_tenants_details =address_2nd_instance[test_netB_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova_netA, nova_instance_details_netA)
        self.nova_instance_deletion(nova_netB, nova_instance_details_netB)
        time.sleep(5)
        self.neutron_network_deletion(test_netA_name)
        self.neutron_network_deletion(test_netB_name)
        assert_equal(status, False)

    def test_cordvtn_creating_public_network_instance_and_validate_connectivity_from_host_machine_or_compute_node(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under public network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under public network
        5. Validate new nova instance is created on nova service
        6. Verify ping is not getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_21_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        test_management_type = "public"
        instance_vm_name = 'vtn_test_21_nova_instance_pulic_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance public ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_public_network_instance_and_validate_connectivity_to_external_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under public network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under public network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_22_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        test_management_type = "public"
        instance_vm_name = 'vtn_test_22_nova_instance_public_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance public ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'], check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_public_network_with_two_instances_and_validate_connectivity_between_two(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under public network
        3. Do GET Rest API and validate creation of network
        4. Create first nova instance under public network
        5. Validate first nova instance is created on nova service
        6. Create second nova instance under public network
        7. Validate second nova instance is created on nova service
        8. Now try to ping from one nova instance to other instance, should not success
        """
        test_net_name = 'vtn_test_23_net_public'
        test_sub_net_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        test_management_type = "public"
        first_instance_vm_name = 'vtn_test_23_nova_1st_instance_public_net'
        second_instance_vm_name = 'vtn_test_23_nova_2nd_instance_public_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        first_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,first_instance_vm_name,image_name,flavor_id)
        second_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,second_instance_vm_name,image_name,flavor_id)
        assert_equal(first_instance_details.status, 'ACTIVE')
        assert_equal(second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print first_nova_instance_details.addresses
        print second_nova_instance_details.addresses
        address_1st_instance = first_nova_instance_details.addresses
        address_2nd_instance = second_nova_instance_details.addresses
        print 'Nova 1st instance public ip = %s'%(address_1st_instance[test_net_name][0]['addr'])
        print 'Nova 2nd instance public ip = %s'%(address_2nd_instance[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_net_name][0]['addr'],source_tenants_details =address_2nd_instance[test_net_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, first_nova_instance_details)
        self.nova_instance_deletion(nova, second_nova_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_two_public_network_instances_and_check_connectvity_between_two_networks_via_public_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under public network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under public network
        5. Validate new nova instance is created on nova service
        """
        test_netA_name = 'vtn_test_24_netA_public'
        test_sub_netA_cidr = ["public","10.6.1.192/26",'10.6.1.193']
        netA_instance_vm_name = 'vtn_test_24_nova_netA_instance_public_net'
        test_netB_name = 'vtn_test_24_netB_public'
        test_sub_netB_cidr = ["public","10.6.2.192/26",'10.6.2.193']
        netB_instance_vm_name = 'vtn_test_24_nova_netB_instance_public_net'
        test_management_type = "public"
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        netA_instance_vm_details = [netA_instance_vm_name, image_name, flavor_id]
        netB_instance_vm_details = [netB_instance_vm_name, image_name, flavor_id]

        nova_netA, nova_instance_details_netA = self.create_net_subnet_nova_instance(test_netA_name, test_sub_netA_cidr, netA_instance_vm_details, test_management_type)
        nova_netB, nova_instance_details_netB = self.create_net_subnet_nova_instance(test_netB_name, test_sub_netB_cidr, netB_instance_vm_details, test_management_type)

        assert_equal(nova_instance_details_netA.status, 'ACTIVE')
        assert_equal(nova_instance_details_netB.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print nova_instance_details_netA.addresses
        print nova_instance_details_netB.addresses
        address_1st_instance = nova_instance_details_netA.addresses
        address_2nd_instance = nova_instance_details_netB.addresses
        print 'Nova 1st instance public ip = %s'%(address_1st_instance[test_netA_name][0]['addr'])
        print 'Nova 2nd instance public ip = %s'%(address_2nd_instance[test_netB_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_netA_name][0]['addr'],source_tenants_details =address_2nd_instance[test_netB_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova_netA, nova_instance_details_netA)
        self.nova_instance_deletion(nova_netB, nova_instance_details_netB)
        time.sleep(5)
        self.neutron_network_deletion(test_netA_name)
        self.neutron_network_deletion(test_netB_name)
        assert_equal(status, False)

    def test_cordvtn_creating_private_network_instance_and_validate_connectivity_from_host_machine_or_compute_node(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under private network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under private network
        5. Validate new nova instance is created on nova service
        6. Verify ping is not getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_25_net_private'
        test_sub_net_cidr = ["private","10.160.160.192/26",'10.160.160.193']
        test_management_type = "private"
        instance_vm_name = 'vtn_test_25_nova_instance_private_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance private ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_private_network_instance_and_validate_connectivity_to_external_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under private network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under private network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_26_net_private'
        test_sub_net_cidr = ["private","10.160.160.192/26",'10.160.160.193']
        test_management_type = "private"
        instance_vm_name = 'vtn_test_26_nova_instance_private_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance private ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'], check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_private_network_with_two_instances_and_check_connectvity_between_two_instances(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under private network
        3. Do GET Rest API and validate creation of network
        4. Create first nova instance under private network
        5. Validate first nova instance is created on nova service
        6. Create second nova instance under public network
        7. Validate second nova instance is created on nova service
        8. Now try to ping from one nova instance to other instance, should not success
        """
        test_net_name = 'vtn_test_27_net_private'
        test_sub_net_cidr = ["private","10.160.160.192/26",'10.160.160.193']
        test_management_type = "private"
        first_instance_vm_name = 'vtn_test_27_nova_1st_instance_private_net'
        second_instance_vm_name = 'vtn_test_27_nova_2nd_instance_private_net'
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        first_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,first_instance_vm_name,image_name,flavor_id)
        second_nova_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,second_instance_vm_name,image_name,flavor_id)
        assert_equal(first_instance_details.status, 'ACTIVE')
        assert_equal(second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print first_nova_instance_details.addresses
        print second_nova_instance_details.addresses
        address_1st_instance = first_nova_instance_details.addresses
        address_2nd_instance = second_nova_instance_details.addresses
        print 'Nova 1st instance private ip = %s'%(address_1st_instance[test_net_name][0]['addr'])
        print 'Nova 2nd instance private ip = %s'%(address_2nd_instance[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_net_name][0]['addr'],source_tenants_details =address_2nd_instance[test_net_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, first_nova_instance_details)
        self.nova_instance_deletion(nova, second_nova_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)

    def test_cordvtn_creating_two_private_network_instances_and_validate_connectivity_between_two_networks_via_private_network(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under private network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under private network
        5. Validate new nova instance is created on nova service
        """
        test_netA_name = 'vtn_test_28_netA_private'
        test_sub_netA_cidr = ["private","10.160.160.192/26",'10.160.160.193']
        netA_instance_vm_name = 'vtn_test_28_nova_netA_instance_private_net'
        test_netB_name = 'vtn_test_28_netB_private'
        test_sub_netB_cidr = ["private","10.160.161.192/26",'10.160.161.193']
        netB_instance_vm_name = 'vtn_test_28_nova_netB_instance_private_net'
        test_management_type = "private"
        image_name = "vsg-1.1"
        flavor_id = 'm1.small'
        netA_instance_vm_details = [netA_instance_vm_name, image_name, flavor_id]
        netB_instance_vm_details = [netB_instance_vm_name, image_name, flavor_id]

        nova_netA, nova_instance_details_netA = self.create_net_subnet_nova_instance(test_netA_name, test_sub_netA_cidr, netA_instance_vm_details, test_management_type)
        nova_netB, nova_instance_details_netB = self.create_net_subnet_nova_instance(test_netB_name, test_sub_netB_cidr, netB_instance_vm_details, test_management_type)

        assert_equal(nova_instance_details_netA.status, 'ACTIVE')
        assert_equal(nova_instance_details_netB.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print 'New nova instance ip addresses are '
        print nova_instance_details_netA.addresses
        print nova_instance_details_netB.addresses
        address_1st_instance = nova_instance_details_netA.addresses
        address_2nd_instance = nova_instance_details_netB.addresses
        print 'Nova 1st instance private ip = %s'%(address_1st_instance[test_netA_name][0]['addr'])
        print 'Nova 2nd instance private ip = %s'%(address_2nd_instance[test_netB_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address_1st_instance[test_netA_name][0]['addr'],source_tenants_details =address_2nd_instance[test_netB_name][0]['addr'], check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova_netA, nova_instance_details_netA)
        self.nova_instance_deletion(nova_netB, nova_instance_details_netB)
        time.sleep(5)
        self.neutron_network_deletion(test_netA_name)
        self.neutron_network_deletion(test_netB_name)
        assert_equal(status, False)

    def test_cordvtn_creating_management_and_public_network_instances_and_validate_connectivity_from_host_machine_or_compute_node_and_validate_connectivity_to_internet(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_two_networks_name = ['vtn_test_29_net_management','vtn_test_29_net_public']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["public","10.6.1.192/26",'10.6.1.193']]
        test_management_type = ["management_local", 'public']
        instance_vm_name = 'vtn_test_29_nova_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_network_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s and public ip %s'%(address[test_two_networks_name[0]][0]['addr'],address[test_two_networks_name[1]][0]['addr'])
        print address[test_two_networks_name[0]][0]['addr']
        print nova.security_groups.list()
        print address[test_two_networks_name[1]][0]['addr']
        print nova.security_groups.list()
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_management_and_public_network_instance_with_and_without_pause_and_validate_connectivity_from_host_machine_or_compute_node_and_validate_connectivity_to_internet(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now pause the nova instance and check connectivity
        8. Now unpause the nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_30_net_management','vtn_test_30_net_public']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["public","10.6.1.192/26",'10.6.1.193']]
        test_management_type = ["management_local", 'public']
        instance_vm_name = 'vtn_test_30_nova_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s and public ip %s'%(address[test_two_networks_name[0]][0]['addr'],address[test_two_networks_name[1]][0]['addr'])
        print address[test_two_networks_name[0]][0]['addr']
        print nova.security_groups.list()
        print address[test_two_networks_name[1]][0]['addr']
        print nova.security_groups.list()
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_instance_details.pause()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_instance_details.unpause()
        print 'Nova instance is paused and unpasued now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_management_and_public_network_instance_doing_suspend_and_resume_validating_connectivity_from_host_machine_or_compute_node_and_validate_connectivity_to_internet(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now suspend the nova instance and check connectivity
        8. Now resume the nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_31_net_management','vtn_test_31_net_public']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["public","10.6.1.192/26",'10.6.1.193']]
        test_management_type = ["management_local", 'public']
        instance_vm_name = 'vtn_test_31_nova_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s and public ip %s'%(address[test_two_networks_name[0]][0]['addr'],address[test_two_networks_name[1]][0]['addr'])
        print address[test_two_networks_name[0]][0]['addr']
        print nova.security_groups.list()
        print address[test_two_networks_name[1]][0]['addr']
        print nova.security_groups.list()
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_instance_details.suspend()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_instance_details.resume()
        print 'Nova instance is suspend and resumed now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_public_network_instance_with_stopping_and_starting_instances_and_checking_connectvity_from_host_machine_or_compute_node_and_validate_connectivity_to_internet(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now stop the nova instance and check connectivity
        8. Now start the nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_32_net_management','vtn_test_32_net_public']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["public","10.6.1.192/26",'10.6.1.193']]
        test_management_type = ["management_local", 'public']
        instance_vm_name = 'vtn_test_32_nova_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s and public ip %s'%(address[test_two_networks_name[0]][0]['addr'],address[test_two_networks_name[1]][0]['addr'])
        print address[test_two_networks_name[0]][0]['addr']
        print nova.security_groups.list()
        print address[test_two_networks_name[1]][0]['addr']
        print nova.security_groups.list()
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_instance_details.stop()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_instance_details.start()
        print 'Nova instance is stopped and started now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_private_network_instance_and_validate_connectivity_from_host_machine_or_compute_node_and_validate_connectivity_to_internet(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_two_networks_name = ['vtn_test_33_net_management','vtn_test_33_net_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193']]
        test_management_type = ["management_local", 'private']
        instance_vm_name = 'vtn_test_33_nova_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s and private ip %s'%(address[test_two_networks_name[0]][0]['addr'],address[test_two_networks_name[1]][0]['addr'])
        print address[test_two_networks_name[0]][0]['addr']
        print nova.security_groups.list()
        print address[test_two_networks_name[1]][0]['addr']
        print nova.security_groups.list()
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()
        status_1, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_to_external")
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, False)

    def test_cordvtn_creating_mgmt_and_private_network_with_two_instances_and_validate_connectivity_from_host_machine_or_compute_node_and_check_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_two_networks_name = ['vtn_test_34_net_management','vtn_test_34_net_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193']]
        test_management_type = ["management_local", 'private']
        first_instance_vm_name = 'vtn_test_34_nova_first_instance_management_net'
        second_instance_vm_name = 'vtn_test_34_nova_second_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[1]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_private_network_with_two_instances_with_and_without_pause_validating_connectivity_from_host_machine_or_compute_node_and_validating_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now pause one of the nova instance and check connectivity
        8. Now start the same nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_35_net_management','vtn_test_35_net_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193']]
        test_management_type = ["management_local", 'private']
        first_instance_vm_name = 'vtn_test_35_nova_first_instance_management_net'
        second_instance_vm_name = 'vtn_test_35_nova_second_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[1]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_first_instance_details.pause()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_first_instance_details.unpause()
        print 'Nova instance is paused and unpased now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_private_network_with_two_instances_and_doing_suspend_and_resume_validating_connectivity_from_host_machine_or_compute_node_and_validating_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now suspend one of the nova instance and check connectivity
        8. Now resume the same nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_36_net_management','vtn_test_36_net_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193']]
        test_management_type = ["management_local", 'private']
        first_instance_vm_name = 'vtn_test_36_nova_first_instance_management_net'
        second_instance_vm_name = 'vtn_test_36_nova_second_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[1]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[1]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_first_instance_details.suspend()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_first_instance_details.resume()
        print 'Nova instance is suspend and resume now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_private_network_with_two_instances_applying_stop_and_start_validating_connectivity_from_host_machine_or_compute_node_and_validating_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Now stop one of the nova instance and check connectivity
        8. Now start the same nova instance and check connectivity
        """
        test_two_networks_name = ['vtn_test_37_net_management','vtn_test_37_net_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193']]
        test_management_type = ["management_local", 'private']
        first_instance_vm_name = 'vtn_test_37_nova_first_instance_management_net'
        second_instance_vm_name = 'vtn_test_37_nova_second_instance_management_net'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,2):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(test_two_networks_name,nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[1]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
        print nova.security_groups.list()
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is False or status_2 is False:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)
        new_first_instance_details.stop()
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        if status_1 is True or status_2 is True:
           self.nova_instance_deletion(nova, new_first_instance_details)
           self.nova_instance_deletion(nova, new_second_instance_details)
           time.sleep(3)
           self.neutron_network_deletion(test_two_networks_name[0])
           self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, False)
        assert_equal(status_2, False)
        new_first_instance_details.start()
        print 'Nova instance is stopped and started now checking connectivity'
        time.sleep(60)
        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_creating_mgmt_and_two_private_network_with_each_instances_and_validate_connectivity_from_host_machine_or_compute_node_and_check_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Verify ping is getting successful after ssh toof one instance to other nova instance which is created in step 4.
        """
        test_two_networks_name = ['vtn_test_39_net_management','vtn_test_39_netA_private','vtn_test_39_netB_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193'], ["private","10.160.161.192/26",'10.160.161.193']]
        test_management_type = ["management_local", 'private','private']
        first_instance_vm_name = 'vtn_test_39_nova_first_instance_management_netA'
        second_instance_vm_name = 'vtn_test_39_nova_second_instance_management_netB'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,3):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(['vtn_test_39_net_management','vtn_test_39_netA_private'],nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(['vtn_test_39_net_management','vtn_test_39_netB_private'],nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[2]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, False)

    def test_cordvtn_service_dependency_without_xos_creating_mgmt_and_two_private_network_with_each_instances_and_validate_connectivity_from_host_machine_or_compute_node_and_check_connectivity_to_other_instance(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        7. Verify ping is getting successful after ssh toof one instance to other nova instance which is created in step 4.
        """
        test_two_networks_name = ['vtn_test_40_net_management','vtn_test_40_netA_private','vtn_test_40_netB_private']
        test_two_sub_networks_cidr = [["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"], ["private","10.160.160.192/26",'10.160.160.193'], ["private","10.160.161.192/26",'10.160.161.193']]
        test_management_type = ["management_local", 'private','private']
        first_instance_vm_name = 'vtn_test_40_nova_first_instance_management_netA'
        second_instance_vm_name = 'vtn_test_40_nova_second_instance_management_netB'
#        image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        for test_net_name in test_two_networks_name:
            result = self.neutron_network_creation_and_validation(test_net_name)
            assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        #for test_net_name,test_sub_net_cidr in test_two_networks_name test_two_sub_networks_cidr:
        for i in range(0,3):
           networks = neutron.list_networks(name=test_two_networks_name[i])
           network_id = self.get_key_value(d=networks, key = 'id')
           sub_result = self.neutron_subnet_creation_and_validation(test_two_networks_name[i],test_two_sub_networks_cidr[i])
           assert_equal(sub_result[0], True)
           net_type_post = self.sub_network_type_post_to_onos(test_two_networks_name[i], test_management_type[i])
           print net_type_post
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        print nova.security_groups.list()
        new_first_instance_details = self.nova_instance_creation_and_validation(['vtn_test_40_net_management','vtn_test_40_netA_private'],nova,first_instance_vm_name,image_name,flavor_id)
        new_second_instance_details = self.nova_instance_creation_and_validation(['vtn_test_40_net_management','vtn_test_40_netB_private'],nova,second_instance_vm_name,image_name,flavor_id)
        time.sleep(60)
        assert_equal(new_first_instance_details.status, 'ACTIVE')
        assert_equal(new_second_instance_details.status, 'ACTIVE')

        service_dependency_post = self.service_dependency_on_network_post_to_onos(test_two_networks_name[1],test_two_networks_name[2],test_management_type[1])
        print service_dependency_post
        compute_details = self.get_compute_nodes()
        first_instance_address = new_first_instance_details.addresses
        second_instance_address = new_second_instance_details.addresses
        print 'Nova first instance management ip = %s and private ip %s'%(first_instance_address[test_two_networks_name[0]][0]['addr'],first_instance_address[test_two_networks_name[1]][0]['addr'])
        print 'Nova second instance management ip = %s and private ip %s'%(second_instance_address[test_two_networks_name[0]][0]['addr'],second_instance_address[test_two_networks_name[2]][0]['addr'])
        secgroup = nova.security_groups.find(name="default")
#        nova.security_group_rules.create(secgroup.id,ip_protocol="tcp",
                                     #from_port="22",
                                     #to_port="22",
                                    # cidr="0.0.0.0/0",)

 #       nova.security_group_rules.create(secgroup.id,
                                    # ip_protocol="icmp",
                                    # from_port=-1,
                                    # cidr="0.0.0.0/0",
                                    # to_port=-1)
        print nova.security_groups.list()

        status_1, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[0]][0]['addr'])
        status_2, output = self.nova_instance_tenants_access_check(first_instance_address[test_two_networks_name[1]][0]['addr'],source_tenants_details = second_instance_address[test_two_networks_name[0]][0]['addr'],check_type = "Ping_from_source_tenant")
        self.nova_instance_deletion(nova, new_first_instance_details)
        self.nova_instance_deletion(nova, new_second_instance_details)
        time.sleep(3)
        self.neutron_network_deletion(test_two_networks_name[0])
        self.neutron_network_deletion(test_two_networks_name[1])
        assert_equal(status_1, True)
        assert_equal(status_2, True)

    def test_cordvtn_management_network_instance_and_validate_connectivity_from_host_machine_or_compute_node_after_br_int_bridge_is_down(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_41_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_41_nova_instance_management_net'
        #image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        if status is False:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(5)
           self.neutron_network_deletion(test_net_name)
        assert_equal(status, True)
        cmd = 'sudo ifconfig br-int down'
        #compute_details = self.get_compute_nodes()
        compute_details = '10.1.0.17'
        ssh_agent = SSHTestAgent(host = compute_details)
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        print output
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        cmd = 'sudo ifconfig br-int up'
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        assert_equal(status, False)

    def test_cordvtn_management_network_instance_and_validate_connectivity_from_host_machine_or_compute_node_toggling_br_int_bridge(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_42_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_42_nova_instance_management_net'
        #image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        cmd = 'sudo ifconfig br-int down'
        #compute_details = self.get_compute_nodes()
        compute_details = '10.1.0.17'
        ssh_agent = SSHTestAgent(host = compute_details)
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        print output
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        if status is True:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(5)
           self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)
        cmd = 'sudo ifconfig br-int up'
        #compute_details = self.get_compute_nodes()
        compute_details = '10.1.0.17'
        ssh_agent = SSHTestAgent(host = compute_details)
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        print output
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, True)

    def test_cordvtn_management_network_instance_and_validate_connectivity_from_host_machine_or_compute_node_checking_onos_flows(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_43_net_management'
        test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_43_nova_instance_management_net'
        #image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
        cmd = 'sudo ifconfig br-int down'
        #compute_details = self.get_compute_nodes()
        compute_details = '10.1.0.17'
        ssh_agent = SSHTestAgent(host = compute_details)
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        print output
        result = self.neutron_network_creation_and_validation(test_net_name)
        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
        assert_equal(sub_result[0], True)
        net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
        assert_equal(new_instance_details.status, 'ACTIVE')
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        self.cliEnter()
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        print flows['IPV4_DST']
        self.cliExit()

        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        if status is True:
           self.nova_instance_deletion(nova, new_instance_details)
           time.sleep(5)
           self.neutron_network_deletion(test_net_name)
        assert_equal(status, False)
        cmd = 'sudo ifconfig br-int up'
        #compute_details = self.get_compute_nodes()
        compute_details = '10.1.0.17'
        ssh_agent = SSHTestAgent(host = compute_details)
        status, output = ssh_agent.run_cmd(cmd, timeout = 5)
        print output
        self.cliEnter()
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        print flows
        self.cliExit()
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, True)
        self.cliEnter()
        flows = json.loads(self.cli.flows(jsonFormat = True))
        flows = filter(lambda f: f['flows'], flows)
        print flows
        self.cliExit()

        ##### We can't test port-create scenarios on CiaB setup.  #### To-DO
    def test_cordvtn_creating_vtn_with_vlan_port_connectivity_and_validate_connectivity_from_host_machine_or_compute_node(self):
        """
        Algo:
        0. Create Test-Net,
        1. Create subnetwork whose ip is under management network
        3. Do GET Rest API and validate creation of network
        4. Create new nova instance under management network
        5. Validate new nova instance is created on nova service
        6. Verify ping is getting successful from compute node to nova instance which is created in step 4.
        """
        test_net_name = 'vtn_test_41_net_vlan_port'
#       test_sub_net_cidr = ["management","172.27.0.0/24", "172.27.0.20", "172.27.0.21"]
#        test_management_type = "management_local"
        instance_vm_name = 'vtn_test_41_nova_instance_vlan_port_net'
        #image_name = "vsg-1.1"
        image_name = "trusty-server-multi-nic"
        flavor_id = 'm1.small'
#        result = self.neutron_network_creation_and_validation(test_net_name)
#        assert_equal(result, True)
        neutron_creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**neutron_creds)
        networks = neutron.list_networks(name=test_net_name)
        network_id = self.get_key_value(d=networks, key = 'id')
#        sub_result = self.neutron_subnet_creation_and_validation(test_net_name,test_sub_net_cidr)
#        assert_equal(sub_result[0], True)
 #       net_type_post = self.sub_network_type_post_to_onos(test_net_name, test_management_type)
        creds = get_nova_credentials()
        nova = nova_client.Client('2', **creds)
#        new_instance_details = self.nova_instance_creation_and_validation(test_net_name,nova,instance_vm_name,image_name,flavor_id)
#        assert_equal(new_instance_details.status, 'ACTIVE')
        #body_port_details = {"port": {"admin_state_up" :"True","device_id" :new_instance_details.id, "name":"stag-100","network_id":network_id}}
        body_port_details = {"port": {"admin_state_up" :"True","device_id" :"", "name":"stag-100","network_id":network_id}}
        response = neutron.create_port(body=body_port_details)
        print(response)
        """
        compute_details = self.get_compute_nodes()
        print new_instance_details.addresses
        address = new_instance_details.addresses
        print 'Nova instance management ip = %s'%(address[test_net_name][0]['addr'])
        time.sleep(60)
        status, output = self.nova_instance_tenants_access_check(address[test_net_name][0]['addr'])
        self.nova_instance_deletion(nova, new_instance_details)
        time.sleep(5)
        self.neutron_network_deletion(test_net_name)
        assert_equal(status, True)
        """

    def test_cordvtn_with_neutron_network_creation_and_validation_on_head_node_with_neutron_service(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Net-1","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        networks = neutron.list_networks(name='Net-1')
        vtn_util = vtn_validation_utils('')
        data = networks
        result = self.search_value(data, "Net-1")
        assert_equal(result, True)

    def test_cordvtn_neutron_network_creation_and_validation_on_onos(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Net-1","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        networks = neutron.list_networks(name='Net-1')
        vtn_util = vtn_validation_utils('')
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "Net-1")
        assert_equal(result, True)

    def test_cordvtn_neutron_network_deletion_and_validation_on_neutron_openstack(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Net-1","admin_state_up":False}}
        net = neutron.delete_network("Net-1")
        networks = neutron.list_networks(name='Net-1')
        vtn_util = vtn_validation_utils('')
        data = networks
        result = self.search_value(data, "Net-1")
        assert_equal(result, True)

    def test_cordvtn_neutron_network_sync(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Test-Net-1","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        url = "http://{0}:8181/onos/cordvtn/serviceNetworks".format(vtn_util.endpoint)
        auth = ('karaf','karaf')
        body_create_subnet = {'subnets': [{'cidr': '192.168.199.0/24',
                             'ip_version': 4, 'network_id': network_id}]}

        subnet = neutron.create_subnet(body=body_create_subnet)

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, "Test-Net-1")
        assert_equal(result, True)

    def test_cordvtn_neutron_port_sync(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created port in cord-onos
        """
        creds = self.get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Test-Net-1","admin_state_up":True}}
        net = neutron.create_network(body=body_example)
        network_id = net['network']['id']
        device_id = 'of:{}'.format(get_mac(self.switch))
        body_example = {'port': {'admin_state_up': True,'device_id':device_id, 'network_id':network_id}}
        response = neutron.create_port(body=body_example)
        url = "http://{0}:8181/onos/cordvtn/servicePorts".format(vtn_util.endpoint)
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)
        result = self.search_value(data, device_id)
        assert_equal(result, True)

    def test_cordvtn_creating_virtual_private_network(self):
	"""
	Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Verify that NetA is being created and validate IP in nova list command.
	    5) Verify that flow is being added in ovs-switch in compute-node.
	    6) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	"""
	pass

    def test_cordvtn_creating_virtual_local_management_network(self):
	"""
	Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Verify that NetA is being created and validate IP in nova list command.
	    5) Verify that flow is being added in ovs-switch in compute-node.
	    6) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	"""
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network(self):
	"""
	Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Verify that NetA is being created and validate IP in nova list command.
	    5) Verify that flow is being added in ovs-switch in compute-node.
	    6) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	"""
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network(self):
	"""
	Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Verify that NetA is being created and validate IP in nova list command.
	    5) Verify that flow is being added in ovs-switch in compute-node.
	    6) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	"""
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network_and_boot_image(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network_and_boot_image(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_2_images_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_2_images_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network_and_boot_2_images_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network_and_boot_2_images_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_connectivity_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_floating_IP_with_vlan_connectivity_network_and_boot_image_connectivity_negative_scenario(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_private_network_and_boot_image_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and private ip on VM.
	    8) Create a same virtual interface with valn tag and  private ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_public_network_and_boot_image_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and public ip on VM.
	    8) Create a same virtual interface with valn tag and any pulic ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_local_management_network_and_boot_image_connectivity(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management ip on VM.
	    8) Create a same virtual interface with valn tag and any local management ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass


    def test_cordvtn_creating_virtual_vlan_interface_floating_private_network_and_boot_image_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and private floating ip on VM.
	    8) Create a same virtual interface with valn tag and  private floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_public_network_and_boot_image_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and public floating ip on VM.
	    8) Create a same virtual interface with valn tag and any pulic floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_local_management_network_and_boot_image_connectivity(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management floating ip on VM.
	    8) Create a same virtual interface with valn tag and any local management floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	    10) verify that ping is successful
	    11) Verify that flow is being added in ovs-switch in compute-node.
	    12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    13) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_public_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the private network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_local_management_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the private network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_vlan_connectivity_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the private network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_floating_IP_with_vlan_connectivity_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the private network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_local_management_other_public_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_vlan_connectivity_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_floating_IP_with_vlan_connectivity_and_a_private_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_vlan_connectivity_other_local_management_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_floating_IP_with_vlan_connectivity_other_local_management_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_one_virtual_floating_IP_with_vlan_connectivity_other_virtual_vlan_network_and_boot_2_images_in_same_service_connectivity_negative_scenario(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in the public network
	    8) verify that ping is not successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	    10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    11) Verify that cord-onos pushed flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_2_images_with_invalid_public_field_of_onos_network_cfg_json_in_same_service(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push network_cfg.json config file to onos with an invalid public gateway ip in network_cfg.json file.
	    4) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Verify ping from VM to public gateway which is send to ONOS through rest API in network_cfg.json file.
	   12) 11th step should be failed due to we are passing invalid public IP as gatway and we have not seen any flows in OVS for it.
	   13) Now ping one VM to other VM it should not ping again even it in the same service.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_with_invalid_localManagementIp_field_of_onos_network_cfg_json(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push network_cfg.json config file to onos with an invalid localManagement ip in network_cfg.json file.
	    4) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    5) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    6) Wait till VM boots up and starts running.
	    7) Verify that a VM is launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Verify ping from VM to local management ip which is send to ONOS through rest API in network_cfg.json file.
	   12) 11th step should be failed due to we are passing invalid local management IP and we have not seen any flows in OVS for it.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image_with_invalid_OVSDB_port_field_of_onos_network_cfg_json(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push network_cfg.json config file to onos with an invalid ovsdb port in network_cfg.json file.
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that flows are  being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos did not push any flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image_with_invalid_OpenStack_details_in_onos_network_cfg_json(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push network_cfg.json config file to onos with an invalid openstack in network_cfg.json file.
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that no flows are being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin is not being received a message from openstack service neutron.
	    9) Verify that cord-onos did not push any flows to OVS switch.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_image_with_invalid_compute_node_details_in_onos_network_cfg_json(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push network_cfg.json config file to onos with an invalid compute node details in network_cfg.json file.
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Verify that no flows are being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin is not being received a message from openstack service neutron.
	    9) Verify that cord-onos did not push any flows to OVS switch.
        """
	pass


    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_in_different_services_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetB with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
	   10) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   11) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_public_networks_and_boot_images_in_different_service_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetB with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	       (neutron net-create net-A-public, neutron subnet-create net-B-public 198.1.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
	   10) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   11) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_local_management_networks_and_boot_images_in_different_service_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetB with an IP as local management network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.28.0.0/24 -gateway 172.28.0.1).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
	   10) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   11) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_vlan_connectivity_networks_and_boot_images_in_different_service_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetB with a vlan port-create.
	       (neutron port-create net-A-private --name stag-100).
	       (neutron port-create net-B-private --name stag-200).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg1-01
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
	   10) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   11) Verify that no flows are being added in the OVS switch.
        """
	pass
    def test_cordvtn_creating_two_virtual_floating_IP_with_vlan_connectivity_networks_and_boot_images_in_different_service_connectivity(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetB with a floating ip and vlan port-create.
	       (neutron port-create net-A-private --name stag-500).
	       (neutron port-create net-B-private --name stag-500).
	    4) Now boot two images in the same created network using nova boot image command (example given below :-
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-01
		   nova boot --image 6ba954df-063f-4379-9e2a-920050879918 --flavor 2 --nic port-id=2c7a397f-949e-4502-aa61-2c9cefe96c74 --user-data passwd.data vsg-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Verify that flow is being added in ovs-switch in compute-node.
	    8) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	    9) Verify that cord-onos pushed flows to OVS switch.
	   10) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   11) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_for_services_dependency_with_out_xos_direct_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push service dependency data.json file to onos to subscriber of other service.
		$ curl -X POST -H "Content-Type: application/json" -u onos:rocks -d @data.json http://$OC1:8181/onos/cordvtn/serviceNetworks
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-A to other VM which is in Net-B, should ping.
	   12) Verify that flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_for_services_dependency_with_out_xos_indirect_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push service dependency data.json file to onos to subscriber of other service.
		$ curl -X POST -H "Content-Type: application/json" -u onos:rocks -d @data.json http://$OC1:8181/onos/cordvtn/serviceNetworks
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-B to other VM which is in Net-A, capture packets on port for ICMP request packets.
	   12) Verify that flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_remove_services_dependency_with_out_xos_direct_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push service dependency data.json file to onos to subscriber of other service.
		$ curl -X POST -H "Content-Type: application/json" -u onos:rocks -d @data.json http://$OC1:8181/onos/cordvtn/serviceNetworks
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-A to other VM which is in Net-B, should ping.
	   12) Verify that flows are being added in the OVS switch.
	   13) Push config data with outservice dependency in data.json file to onos to subscriber of other service.
	   14) Now ping from VM which is Net-A to other VM which is in Net-B, should not ping.
	   15) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_remove_services_dependency_with_out_xos_indirect_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push service dependency data.json file to onos to subscriber of other service.
		$ curl -X POST -H "Content-Type: application/json" -u onos:rocks -d @data.json http://$OC1:8181/onos/cordvtn/serviceNetworks
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-B to other VM which is in Net-A, capture packets on port for ICMP request packets.
	   12) Verify that flows are being added in the OVS switch.
	   13) Push config data with out service dependency in data.json file to onos to subscriber of other service.
	   14) Now ping from VM which is Net-B to other VM which is in Net-A, should not see any ICMP request packets on port.
	   15) Verify that no flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_for_services_dependency_with_xos_direct_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Validate that XOS is up and running.
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-A to other VM which is in Net-B, should ping.
	   12) Verify that flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_creating_two_virtual_private_networks_and_boot_images_for_services_dependency_with_xos_indirect_access(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Validate that XOS is up and running.
	    4) From CORD-Test container, use python-neutron client and create two networks with name - NetA and NetBwith an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	       (neutron net-create net-B-private, neutron subnet-create net-B-private 10.1.0.0/24).
	    5) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-B-vm-01
	    6) Wait till VMs boot up and running.
	    7) Verify that two VMs are launched and running by using novaclient python API.
	    8) Verify that flow is being added in ovs-switch in compute-node.
	    9) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   10) Verify that cord-onos pushed flows to OVS switch.
	   11) Now ping from VM which is Net-B to other VM which is in Net-A, should ping.
	   12) Verify that flows are being added in the OVS switch.
        """
	pass

    def test_cordvtn_with_access_agent_serviceType_and_vtn_location_field_network_cfg_connectivity_to_access_device(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push access-agent additional network_cfg to ONOS and specify vtn-location field info must be access-agent container.
	    4) Launch the access-agent and access-device containers and then restart openstack compute node.
	       $ sudo docker run --privileged --cap-add=ALL -d --name access-agent -t ubuntu:14.04 /bin/bash
	    5) Create each interface on br-int and br-mgmt using pipework on access-agent containers
	       $ sudo ./pipework br-mgmt -i eth1 access-agent 10.10.10.20/24
	       $ sudo ./pipework br-int -i eth2 access-agent 10.168.0.100/24 fa:00:00:00:00:11
	    6) We ahve to stop ONOS service to test this
		 onos-service stop
		 sudo ovs-ofctl -O OpenFlow13 del-flows br-int "arp"
	    7) Now attach to access-agent container and ping to access-device
	    8) Verify that ping should be success and flows are being added in br-int.
        """
	pass

    def test_cordvtn_with_access_agent_serviceType_and_vtn_location_field_in_network_cfg_connectivity_to_head_node(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push access-agent additional network_cfg to ONOS and specify vtn-location field info must be access-agent container.
	    4) Launch the access-agent and access-device containers and then restart openstack compute node.
	       $ sudo docker run --privileged --cap-add=ALL -d --name access-agent -t ubuntu:14.04 /bin/bash
	    5) Create each interface on br-int and br-mgmt using pipework on access-agent containers
	       $ sudo ./pipework br-mgmt -i eth1 access-agent 10.10.10.20/24
	       $ sudo ./pipework br-int -i eth2 access-agent 10.168.0.100/24 fa:00:00:00:00:11
	    6) We ahve to stop ONOS service to test this
		 onos-service stop
		 sudo ovs-ofctl -O OpenFlow13 del-flows br-int "arp"
	    7) Now attach to access-agent container and ping to head node
	    8) Verify that ping should be success and flows are being added in br-int.
        """
	pass

    def test_cordvtn_with_access_agent_serviceType_and_invalid_vtn_location_field_network_cfg_connectivity_to_access_device(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push access-agent additional network_cfg to ONOS and specify vtn-location field info must not be access-agent container.
	    4) Launch the access-agent and access-device containers and then restart openstack compute node.
	       $ sudo docker run --privileged --cap-add=ALL -d --name access-agent -t ubuntu:14.04 /bin/bash
	    5) Create each interface on br-int and br-mgmt using pipework on access-agent containers
	       $ sudo ./pipework br-mgmt -i eth1 access-agent 10.10.10.20/24
	       $ sudo ./pipework br-int -i eth2 access-agent 10.168.0.100/24 fa:00:00:00:00:11
	    6) We ahve to stop ONOS service to test this
		 onos-service stop
		 sudo ovs-ofctl -O OpenFlow13 del-flows br-int "arp"
	    7) Now attach to access-agent container and ping to access-device
	    8) Verify that ping should not be success and no flows are being added in br-int.
        """
	pass

    def test_cordvtn_with_access_agent_serviceType_and_invalid_vtn_location_field_in_network_cfg_connectivity_to_head_node(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) Push access-agent additional network_cfg to ONOS and specify vtn-location field info must not be access-agent container.
	    4) Launch the access-agent and access-device containers and then restart openstack compute node.
	       $ sudo docker run --privileged --cap-add=ALL -d --name access-agent -t ubuntu:14.04 /bin/bash
	    5) Create each interface on br-int and br-mgmt using pipework on access-agent containers
	       $ sudo ./pipework br-mgmt -i eth1 access-agent 10.10.10.20/24
	       $ sudo ./pipework br-int -i eth2 access-agent 10.168.0.100/24 fa:00:00:00:00:11
	    6) We ahve to stop ONOS service to test this
		 onos-service stop
		 sudo ovs-ofctl -O OpenFlow13 del-flows br-int "arp"
	    7) Now attach to access-agent container and ping to head node
	    8) Verify that ping should not be success and no flows are being added in br-int.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service_connectivity_after_restarting_VMs(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart both VMs in same service and repeat steps 7 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service_connectivity_after_restarting_cord_onos(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart ONOS service and repeat steps 7 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service_connectivity_after_delete_any_VM_recreating_it(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete a VM which was created earlier and repeat steps 4 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_private_network_and_boot_2_images_in_same_service_connectivity_after_delete_and_add_br_int_bridge(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as private network.
	       (neutron net-create net-A-private, neutron subnet-create net-A-private 10.0.0.0/24).
	    4) Now boot 2 images in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-02
	    5) Wait till VMs boot up and running.
	    6) Verify that two VMs are launched and running by using novaclient python API.
	    7) Now ping to the VM from other VM which are launched in same network
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete a br_int bridge and repeat steps 7 to 11, (it should not ping)
	   13) Add br_int bridge and repeat steps 7 to 11, (it should ping)
        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity_after_restarting_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart the VM in service and repeat steps 7 to 11.

        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity_after_restarting_cord_onos(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart onos service container and repeat steps 7 to 11.

        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity_after_delete_and_recreate_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete and re-create a VM in the same service and repeat steps 7 to 11.

        """
	pass

    def test_cordvtn_creating_virtual_public_network_and_boot_image_connectivity_after_delete_and_add_br_int_bridge(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		$ nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from outside network which are internet network (global ping)
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete a br_int bridge and repeat steps 7 to 11, (it should not ping)
	   13) Add br_int bridge and repeat steps 7 to 11, (it should ping)

        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity_after_restarting_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart the VM in service and repeat steps 7 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity_after_restarting_cord_onos(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Restart the onos service and repeat steps 7 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity_after_delete_and_recreate_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete and re-create a VM in the same service and repeat steps 7 to 11.
        """
	pass

    def test_cordvtn_creating_virtual_local_management_network_and_boot_image_connectivity_after_delete_and_add_br_int_bridge(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Now ping to the VM from compute node network which are launched a VM.
	    8) verify that ping is successful
	    9) Verify that flow is being added in ovs-switch in compute-node.
	   10) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   11) Verify that cord-onos pushed flows to OVS switch.
	   12) Delete a br_int bridge and repeat steps 7 to 11, (it should not ping)
	   13) Add br_int bridge and repeat steps 7 to 11, (it should ping)
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_local_management_network_and_boot_image_connectivity_after_restarting_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management ip on VM.
	    8) Create a same virtual interface with valn tag and any local management ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Restart the VM in service and repeat steps 9 to 13.

        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_local_management_network_and_boot_image_connectivity_after_restarting_cord_onos(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management ip on VM.
	    8) Create a same virtual interface with valn tag and any local management ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Restart the ONOS service and repeat steps 9 to 13.

        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_local_management_network_and_boot_image_connectivity_after_delete_and_recreate_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management ip on VM.
	    8) Create a same virtual interface with valn tag and any local management ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Delete and re-create a VM in service and repeat steps 9 to 13.

        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_local_management_network_and_boot_image_connectivity_after_delete_and_add_br_int_bridge(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management ip on VM.
	    8) Create a same virtual interface with valn tag and any local management ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Delete a br_int bridge and repeat steps 9 to 13, (it should not ping)
	   15) Add br_int bridge and repeat steps 9 to 13, (it should ping)

        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_local_management_network_and_boot_image_connectivity_after_restarting_VM(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management floating ip on VM.
	    8) Create a same virtual interface with valn tag and any local management floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Restart the VM in service and repeat steps 9 to 13.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_local_management_network_and_boot_image_connectivity_after_restarting_cord_onos(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management floating ip on VM.
	    8) Create a same virtual interface with valn tag and any local management floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Restart the ONOS service and repeat steps 9 to 13.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_local_management_network_and_boot_image_connectivity_after_delete_and_recreate_VM(self):
        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management floating ip on VM.
	    8) Create a same virtual interface with valn tag and any local management floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Delete and re-create a VM in service and repeat steps 9 to 13.
        """
	pass

    def test_cordvtn_creating_virtual_vlan_interface_floating_local_management_network_and_boot_image_connectivity_after_delete_and_add_br_int_bridge(self):

        """
	 Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as local management  network.
	       (neutron net-create net-A-management, neutron subnet-create net-A-management 172.27.0.0/24 -gateway 172.27.0.1).
	    4) Now boot image in the same created network using nova boot image command (example given below :-
		 nova boot --image 3e2d7760-774a-4a16-be07-aaccafa779b6 --flavor 1 --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de --nic net-id=8bc19377-f493-4cad-af23-45fb299da9de net-A-vm-01
	    5) Wait till VM boots up and starts running.
	    6) Verify that a VM is launched and running by using novaclient python API.
	    7) Create a virtual interface with vlan tag and local management floating ip on VM.
	    8) Create a same virtual interface with valn tag and any local management floating ip on head node.
	    9) Now ping to the VM from head node network which are launched a openstack service.
	   10) verify that ping is successful
	   11) Verify that flow is being added in ovs-switch in compute-node.
	   12) Verify that onos-ml2 plugin syncs through ReST call  from openstack service neutron.
	   13) Verify that cord-onos pushed flows to OVS switch.
	   14) Delete a br_int bridge and repeat steps 9 to 13, (it should not ping)
	   15) Add br_int bridge and repeat steps 9 to 13, (it should ping)
        """
	pass

