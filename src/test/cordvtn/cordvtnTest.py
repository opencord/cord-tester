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

class cordvtn_exchange(CordLogger):

    app_cordvtn = 'org.opencord.vtn'
    test_path = os.path.dirname(os.path.realpath(__file__))
    cordvtn_dir = os.path.join(test_path, '..', 'setup')
    cordvtn_conf_file = os.path.join(test_path, '..', '../cordvtn/network_cfg.json')
    default_config = { 'default-lease-time' : 600, 'max-lease-time' : 7200, }
    default_options = [ ('subnet-mask', '255.255.255.0'),
                     ('broadcast-address', '192.168.1.255'),
                     ('domain-name-servers', '192.168.1.1'),
                     ('domain-name', '"mydomain.cord-tester"'),
                   ]
    default_subnet_config = [ ('192.168.1.2',
'''
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.10 192.168.1.100;
}
'''), ]
    config = {}

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

    def create_router(self, name):
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
        router = self.neutron.create_router(router_info)['router']
        return router

    def router_add_gateway( router_name, network_name):
        pass

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

    @classmethod
    def verify_neutron_crud():
        x = os.system("neutron_test.sh")
        return x

    def test_cordvtn_app_activation(self):
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

    def test_cordvtn_basic_tenant(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"
        assert_equal(status, True)

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret1 != 0:
           print "Creation of Tenant netB Failed"
        assert_equal(ret1, ret2)

    def test_cordvtn_for_create_network(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

        ret1 = create_tenant(netA)
        if ret1 != 0:
           print "Creation of Tenant netA Failed"

        ret2 = create_tenant(netB)
        if ret2 != 0:
           print "Creation of Tenant netB Failed"
        network = {'name': self.network_name, 'admin_state_up': True}
        self.neutron.create_network({'network':network})
        log.info("Created network:{0}".format(self.network_name))
        assert_equal(ret1, ret2)

    def test_cordvtn_to_create_net_work_with_subnet(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

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
        assert_equal(ret1, ret2)

    def test_cordvtn_subnet_limit(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

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
        assert_equal(ret1, ret2)

    def test_cordvtn_floatingip_limit(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

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
        assert_equal(ret1, ret2)

    def test_cordvtn_10_neutron_networks(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

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
        assert_equal(ret1, ret2)

    def test_cordvtn_100_neutron_networks(self):
        onos_load_config()
        status = verify_neutron_crud()
        if status != 0:
           print "Issues with Neutron working state"

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
        assert_equal(ret1, ret2)

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

