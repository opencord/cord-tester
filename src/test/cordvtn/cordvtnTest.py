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

    @classmethod
    def get_neutron_credentials():
        n = {}
        n['username'] = os.environ['OS_USERNAME']
        n['password'] = os.environ['OS_PASSWORD']
        n['auth_url'] = os.environ['OS_AUTH_URL']
        n['tenant_name'] = os.environ['OS_TENANT_NAME']
        return n

    @classmethod
    def create_net(tenant_id, name, shared="", external=""):
        cmd = "neutron net-create %s %s %s --tenant-id=%s"%(name, shared, external, tenant_id)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def create_subnet(tenant_id, name, subnet, dhcp=""):
        cmd = "neutron subnet-create %s %s --name %s %s --tenant-id=%s"%(net, subnet, name, dhcp, tenant_id)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def del_net( tenant_id, name):
        cmd = "neutron net-delete %s --tenant-id=%s"%(name, tenant_id)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def del_subnet( tenant_id, name):
        cmd =  "neutron subnet-create %s %s --name %s %s --tenant-id=%s"%(net,subnet,name, dhcp, tenant_id)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def create_net_and_subnet():
        network_name = "Subscriber-1"

        creds = get_neutron_credentials()
        neutron = client.Client(**creds)

	body_example = {
	       "network":
	     {
	       "name": network_name,
	       "admin_state_up":True
	     }
	}
	net = neutron.create_network(body=body_example)
	net_dict = net['network']
	network_id = net_dict['id']
	print "Network %s created" %network_id

	create_subnet = {
	      "subnets": [
	        {
	          "cidr":"10.10.0.0/24",
	          "ip_version":4,
	          "network_id":network_id
	        }
	      ]
	}
	subnet = neutron.create_subnet(body = create_subnet)
	print "Created Subnet %s"%subnet

    @classmethod
    def create_network(i):
        neutron_credentials = get_neutron_credentials()
        neutron = neutron_client.Client(**neutron_credentials)
        json = {'network': {'name': 'network-' + str(i),
                            'admin_state_up': True}}
        while True:
           try:
              neutron.create_network(body=json)
              print '\nnetwork-' + str(i) + ' created'
              break
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

    @classmethod
    def get_id(tenant_id, name):
        cmd = "neutron %s-list --tenant-id=%s"%(objname,sdn_tenant_id)
        output = os.system(cmd)
        lis = output.split("\n")
        for i in lis:
            tokens = i.split()
        if len(tokens)>3 and tokens[3] == name:
           return tokens[1]
        return none

    @classmethod
    def nova_boot(tenant_id, name, netid=None, portid=None):
        if netid:
           cmd = "nova --os-tenant-id %s boot --flavor 1 --image %s --nic net-id=%s %s"%(tenant_id, vm_image_id,netid,name)
        if portid:
           cmd = "nova --os-tenant-is %s boot --flavor 1 --image %s --nic port-id=%s %s"%(tenant_id,vm_image_id,portid,name)
        os.system(cmd)

    @classmethod
    def port_create(sdn_tenant_id,name, net, fixedip, subnetid):
        cmd = "neutron port-create --name %s --fixed-ip subnet_id=%s,ip_address=%s --tenant-id=%s %s" %(name,subnetid,fixedip,sdn_tenant_id,net)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def nova_wait_boot(sdn_tenant_id,name, state, retries=10):
        global errno
        cmd = "nova --os-tenant-id %s list" %(sdn_tenant_id)
        for i in range(retries):
            out = os.system(cmd)
            lis = out.split("\n")
            for line in lis:
                toks = line.split()
                if len(toks) >= 5 and toks[3] == name and toks[5] == state:
                   return
            time.sleep(5)
        errno=1

    @classmethod
    def port_delete(sdn_tenant_id,name):
        cmd = "neutron port-delete %s" %(name)
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def tenant_delete(name):
        cmd = "keystone tenant-delete %s"%(name)
        os.system(cmd)
        time.sleep(1)

    @classmethod
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
            pool.apply_asynch(create_network, (i, ))

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
            pool.apply_asynch(create_network, (i, ))

        pool.close()
        pool.join()
        status = validate_vtn_flows()
        assert_equal(status, True)

    def test_cordvtn_nodes(self):
        pass

    def test_cordvtn_networks(self):
        pass

    def test_cordvtn_for_range_of_networks(self):
        pass

    def test_cordvtn_node_check(self):
        pass

    def test_cordvtn_init(self):
        pass

    def test_cordvtn_ports(self):
        pass

    def test_cordvtn_synching_neutron_states(self):
        pass

    def test_cordvtn_synching_xos_states(self):
        pass

    def test_cordvtn_config_on_restart(self):
        pass

    def test_cordvtn_arp_proxy(self):
        pass

    def test_cordvtn_gateway(self):
        pass

    def test_cordvtn_openstack_access(self):
        pass

    def test_cordvtn_xos_access(self):
        pass

    def test_cordvtn_ssh_access(self):
        pass

    def test_cordvtn_ovsdbport(self):
        pass

    def test_cordvtn_local_management_ip(self):
        pass

    def test_cordvtn_compute_nodes(self):
        pass

    def test_cordvtn_service_dependency_for_two_subnets(self):
        pass

    def test_cordvtn_service_dependency_for_three_subnets(self):
        pass

    def test_cordvtn_service_dependency_for_four_subnets(self):
        pass

    def test_cordvtn_service_dependency_for_five_subnets(self):
        pass

    def test_cordvtn_for_biderectional_connections(self):
        pass

    def test_cordvtn_authentication_from_openstack(self):
        pass

    def test_cordvtn_with_gateway(self):
        pass

    def test_cordvtn_without_gateway(self):
        pass

    def test_cordvtn_for_service_instance(self):
        pass

    def test_cordvtn_for_instance_to_network(self):
        pass

    def test_cordvtn_for_network_to_instance(self):
        pass

    def test_cordvtn_for_instance_to_instance(self):
        pass

    def test_cordvtn_for_network_to_network(self):
        pass

    def test_cordvtn_without_neutron_ml2_plugin(self):
        pass

    def test_cordvtn_with_neutron_ml2_plugin(self):
        pass

    def test_cordvtn_service_network_type_private(self):
        pass

    def test_cordvtn_service_network_type_management_local(self):
        pass

    def test_cordvtn_service_network_type_management_host(self):
        pass

    def test_cordvtn_service_network_type_vsg(self):
        pass

    def test_cordvtn_service_network_type_access_agent(self):
        pass

    def test_cordvtn_mgmt_network(self):
        pass

    def test_cordvtn_data_network(self):
        pass

    def test_cordvtn_public_network(self):
        pass

    def test_cordvtn_in_same_network(self):
        pass

    def test_cordvtn_local_mgmt_network(self):
        pass

    def test_cordvtn_service_dependency(self):
        pass

    def test_cordvtn_service_dependency_with_xos(self):
        pass

    def test_cordvtn_vsg_xos_service_profile(self):
        pass

    def test_cordvtn_access_agent(self):
        pass

    def test_cordvtn_network_creation(self):
        pass

    def test_cordvtn_network_deletion(self):
        pass

    def test_cordvtn_removing_service_network(self):
        pass

    def test_cordvtn_web_application(self):
        pass

    def test_cordvtn_service_port(self):
        pass

    def test_cordvtn_inetgration_bridge(self):
        pass

