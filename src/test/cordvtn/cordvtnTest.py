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
from multiprocessing import Pool
from neutronclient.v2_0 import client as neutron_client
from nose.tools import assert_equal
from OnosCtrl import OnosCtrl, get_mac
from CordLogger import CordLogger
import time
import py_compile

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

    endpoint = "http://172.17.0.2:8101"
    version=""
    def __init__(self, version):
        self.version = version
        self.devices = '/onos/v1/devices'
        self.links = '/onos/v1/links'
        self.flows = '/onos/v1/flows'
        self.apps = '/onos/v1/applications'

    def getDevices(self, endpoint, user, passwd):
        headers = {'Accept': 'application/json'}
        url = endpoint+self.devices
        response = requests.get(url, headers=headers, auth=(user, passwd))
        response.raise_for_status()
        return response.json()

    def getLinks(self, endpoint, user, passwd):
        headers = {'Accept': 'application/json'}
        url = endpoint+self.links
        response = requests.get(url, headers=headers, auth=(user, passwd))
        response.raise_for_status()
        return response.json()

    def getDevicePorts(self, endpoint, user, passwd, switch_id):
        headers = {'Accept': 'application/json'}
        url = endpoint+self.devices+"/"+str(switch_id)+"/ports"
        response = requests.get(url, headers=headers, auth=(user, passwd))
        response.raise_for_status()
        return response.json()

    def activateVTNApp(self, endpoint, user, passwd, app_name):
        headers = {'Accept': 'application/json'}
        url = endpoint+self.apps+"/"+str(app_name)+"/active"
        response = requests.post(url, headers=headers, auth=(user, passwd))
        response.raise_for_status()
        return response.json()

    def deactivateVTNApp(self, endpoint, user, passwd, app_name):
        headers = {'Accept': 'application/json'}
        url = endpoint+self.apps+"/"+str(app_name)+"/active"
        response = requests.delete(url, headers=headers, auth=(user, passwd))
        response.raise_for_status()
        return response.json()

class cordvtn_exchange(CordLogger):

    app_cordvtn = 'org.opencord.vtn'
    test_path = os.path.dirname(os.path.realpath(__file__))
    cordvtn_dir = os.path.join(test_path, '..', 'setup')
    cordvtn_conf_file = os.path.join(test_path, '..', '../cordvtn/network_cfg.json')

    @classmethod
    def setUpClass(cls):
        ''' Activate the cordvtn app'''
        time.sleep(3)
        cls.onos_ctrl = OnosCtrl(cls.app_cordvtn)
        status, _ = cls.onos_ctrl.activate()
        assert_equal(status, False)
        time.sleep(3)
        cls.cordvtn_setup()

    @classmethod
    def tearDownClass(cls):
        '''Deactivate the cord vtn app'''
        cls.onos_ctrl.deactivate()
        cls.cord_vtn_cleanup()

    @classmethod
    def cordvtn_setup(cls):
        pass

    @classmethod
    def cord_vtn_cleanup(cls):
        ##reset the ONOS port configuration back to default
        for config in cls.configs.items():
            OnosCtrl.delete(config)

    @classmethod
    def onos_load_config(cls, cordvtn_conf_file):
        status, code = OnosCtrl.config(cordvtn_conf_file)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

    def get_neutron_credentials():
        n = {}
        n['username'] = os.environ['OS_USERNAME']
        n['password'] = os.environ['OS_PASSWORD']
        n['auth_url'] = os.environ['OS_AUTH_URL']
        n['tenant_name'] = os.environ['OS_TENANT_NAME']
        return n

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
        flow_id = flow.findFlow(device_id, IN_PORT = ('port', ingress),
                                ETH_TYPE = ('ethType','0x800'), IPV4_SRC = ('ip', ingress_map['ip']+'/32'),
                                IPV4_DST = ('ip', egress_map['ip']+'/32'))
        if flow_id:
           return True

    def cordvtn_config_load(self, config = None):
        if config:
           for k in config.keys():
               if cordvtn_config.has_key(k):
                  cordvtn_config[k] = config[k]
        self.onos_load_config(self.cordvtn_dict)

    def search_value(d, pat):
        for k, v in d.items():
            if isinstance(v, dict):
               search_value(v, pat)
            else:
               if v == pat:
                  print "Network created successfully"
                  return True
               else:
                  return False

    def test_cordvtn_neutron_network_sync(self):
        """
        Algo:
        0. Create Test-Net,
        1. Load cordvtn config, vtn-cfg-1.json to cord-onos
        2. Run sync command for cordvtn
        3. Do GET Rest API and validate creation of network
        4. Validate network synch with created network in cord-onos
        """

        vtnconfig = {
         "apps" : {
           "org.opencord.vtn" : {
             "cordvtn" : {
               "controllers" : [ "10.1.0.1:6654" ],
               "localManagementIp" : "172.27.0.1/24",
               "nodes" : [ {
                 "bridgeId" : "of:0000525400201852",
                 "dataPlaneIntf" : "fabric",
                 "dataPlaneIp" : "10.6.1.2/24",
                 "hostManagementIp" : "10.1.0.14/24",
                 "hostname" : "cold-flag"
               } ],
               "openstack" : {
                 "endpoint" : "https://keystone.cord.lab:5000/v2.0",
                 "password" : "VeryLongKeystoneAdminPassword",
                 "tenant" : "admin",
                 "user" : "admin"
               },
               "ovsdbPort" : "6641",
               "privateGatewayMac" : "00:00:00:00:00:01",
               "publicGateways" : [ {
                 "gatewayIp" : "10.6.1.193",
                 "gatewayMac" : "02:42:0a:06:01:01"
               }, {
                 "gatewayIp" : "10.6.1.129",
                 "gatewayMac" : "02:42:0a:06:01:01"
               } ],
               "ssh" : {
                 "sshKeyFile" : "/root/node_key",
                 "sshPort" : "22",
                 "sshUser" : "root"
               },
               "xos" : {
                 "endpoint" : "http://xos:8888/",
                 "password" : "letmein",
                 "user" : "padmin@vicci.org"
               }
             }
           }
         }
        }

        self.onos_load_config(vtnconfig)
        creds = get_neutron_credentials()
        neutron = neutronclient.Client(**creds)
        body_example = {"network":{"name": "Test-Net","admin_state_up":True}}
        net = neutron.create_network(body=body_example)

        url = "http://172.17.0.2/onos/cordvtn/serviceNetworks"
        auth = ('karaf','karaf')

        resp = requests.get(url=url, auth=auth)
        data = json.loads(resp.text)

        result = search_response(data, "Test-Net")
        assert_equal(result, True)

    def test_cordvtn_basic_tenant(self):
        onos_load_config()

        tenant_1= create_tenant("CORD_Subscriber_Test_Tenant_1")
        if tenant1 != 0:
           print "Creation of CORD Subscriber Test Tenant 1"

        tenant_2 = create_tenant("CORD_Subscriber_Test_Tenant_2")
        if tenant2 != 0:
           print "Creation of CORD Subscriber Test Tenant 2"

        create_net(tenant_1,"a1")
        create_subnet(tenant_1,"a1","as1","10.0.1.0/24")

        create_net(tenant_2,"a2")
        create_subnet(tenant_2,"a2","as1","10.0.2.0/24")

        netid_1 = get_id(tenant_1,"net","a1")
        netid_2 = get_id(tenant_2,"net","a2")

        nova_boot(tenant_1,"vm1",netid=netid)
        nova_boot(tenant_2,"vm1",netid=netid)

	nova_wait_boot(tenant_1,"vm1", "ACTIVE")
	nova_wait_boot(tenant_2,"vm1", "ACTIVE")

        router_create(tenant_1,"r1")
        router_interface_add(tenant_1,"r1","as1")
        router_create(tenant_2,"r1")
        router_interface_add(tenant_2,"r1","as1")

        create_net(tenant_1,"x1","","--router:external=True")
        create_net(tenant_2,"x1","","--router:external=True")

        router_gateway_set(tenant_1,"r1","x1")
        router_gateway_set(tenant_2,"r1","x1")

        subnetid_1 = get_id(tenant_1,"subnet","as1")
        subnetid_2 = get_id(tenant_2,"subnet","as1")
        port_create(tenant_1,"p1","a1","10.0.1.100",subnetid_1)
        port_create(tenant_2,"p1","a1","10.0.1.100",subnetid_2)

        port_id_1 = get_id(tenant_1,"port","p1")
        port_id_2 = get_id(tenant_2,"port","p1")
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_for_creation_of_network(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        network = {'name': self.network_name, 'admin_state_up': True}
        self.neutron.create_network({'network':network})
        log.info("Created network:{0}".format(self.network_name))
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_to_create_net_work_with_subnet(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        network_name = self.network_name
        network = {'name': network_name, 'admin_state_up': True}
        network_info = self.neutron.create_network({'network':network})
        network_id = network_info['network']['id']

        log.info("Created network:{0}".format(network_id))
        self.network_ids.append(network_id)
        subnet_count = 1
        for cidr in self.subnet_cidrs:
            gateway_ip = str(list(cidr)[1])
            subnet = {"network_id": network_id, "ip_version":4,
                      "cidr":str(cidr), "enable_dhcp":True,
                      "host_routes":[{"destination":"0.0.0.0/0", "nexthop":gateway_ip}]
                     }
            subnet = {"name":"subnet-"+str(subnet_count), "network_id": network_id, "ip_version":4, "cidr":str(cidr), "enable_dhcp":True}
            print subnet
            self.neutron.create_subnet({'subnet':subnet})
            log.info("Created subnet:{0}".format(str(cidr)))
            if not self.number_of_subnet - 1:
                break
        self.number_of_subnet -= 1
        subnet_count += 1
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_subnet_limit(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        network_name = uuid.uuid4().get_hex()
        network = {'name': network_name, 'admin_state_up': True}
        network_info = self.neutron.create_network({'network':network})
        log.info("Created network:{0}".format(network_name))
        network_id = network_info['network']['id']
        self.network_ids.append(network_id)
        subnet_cidrs = ['11.2.2.0/29',  '11.2.2.8/29']
        for cidr in subnet_cidrs:
            subnet = {"network_id": network_id, "ip_version":4, "cidr": cidr}
            subnet_info = self.neutron.create_subnet({'subnet':subnet})
            subnet_id = subnet_info['subnet']['id']
            log.info("Created subnet:{0}".format(cidr))
        while True:
            port = {"network_id": network_id, "admin_state_up": True}
            port_info = self.neutron.create_port({'port':port})
            port_id = port_info['port']['id']
            self.port_ids.append(port_id)
            log.info("Created Port:{0}".format(port_info['port']['id']))
            if not self.quota_limit:
               break
            self.quota_limit -= 1
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_floatingip_limit(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        while True:
            floatingip = {"floating_network_id": self.floating_nw_id}
            fip_info = self.neutron.create_floatingip({'floatingip':floatingip})
            fip_id = fip_info['floatingip']['id']
            log.info("Created Floating IP:{0}".format(fip_id))
            self.fip_ids.append(fip_id)
            if not self.quota_limit:
               break
            self.quota_limit -= 1
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_for_10_neutron_networks(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        pool = Pool(processes=10)
        ret = os.system("neutron quote-update --network 15")
        if ret1 != 0:
           print "Neutron network install failed"
        for i in range(1, 11):
            pool.apply_async(create_network, (i, ))

        pool.close()
        pool.join()
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_for_100_neutron_networks(self):
        onos_load_config()

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        pool = Pool(processes=10)

        ret = os.system("neutron quote-update --network 105")
        if ret1 != 0:
           print "Neutron network install failed"
        for i in range(1, 101):
            pool.apply_async(create_network, (i, ))

        pool.close()
        pool.join()
        status = validate_vtn_flows()
        assert_equal(status, True)

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

    def test_cordvtn_creating_virtual_public_network(self):
	"""
	Algo:
	    1) Validate that required openstack service is up and running.
	    2) Validate that compute node is being created and get compute node name by using "sudo cord prov list".
	    3) From CORD-Test container, use python-neutron client and create network with name - NetA with an IP as public network.
	       (neutron net-create net-A-public, neutron subnet-create net-A-public 198.0.0.0/24).
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
