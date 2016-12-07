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
import os
import keystoneclient.v2_0.client as ksclient
import keystoneclient.apiclient.exceptions
import neutronclient.v2_0.client as nclient
import neutronclient.common.exceptions
import novaclient.v1_1.client as novaclient
from multiprocessing import Pool
from nose.tools import assert_equal
from CordLogger import CordLogger
log.setLevel('INFO')

class cordvtn_exchange(CordLogger):

    app = 'org.opencord.cordvtn'

    @classmethod
    def setUpClass(cls):
        cls.olt = OltConfig()
        cls.port_map, _ = cls.olt.olt_port_map()
        if not cls.port_map:
            cls.port_map = g_subscriber_port_map
        cls.iface = cls.port_map[1]

    def setUp(self):
        ''' Activate the cord vtn app'''
        super(dhcp_exchange, self).setUp()
        self.maxDiff = None ##for assert_equal compare outputs on failure
        self.onos_ctrl = OnosCtrl(self.app)
        status, _ = self.onos_ctrl.activate()
        assert_equal(status, True)
        time.sleep(3)

    def tearDown(self):
        '''Deactivate the cord vtn app'''
        self.onos_ctrl.deactivate()
        super(dhcp_exchange, self).tearDown()

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        time.sleep(3)

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

    def get_neutron_credentials():
        d = {}
        d['username'] = os.environ['OS_USERNAME']
        d['password'] = os.environ['OS_PASSWORD']
        d['auth_url'] = os.environ['OS_AUTH_URL']
        d['tenant_name'] = os.environ['OS_TENANT_NAME']
        return d


    def create_network(i):
        neutron_credentials = get_neutron_credentials()
        neutron = neutron_client.Client(**neutron_credentials)
        json = {'network': {'name': 'network-' + str(i),
                'admin_state_up': True}}
        while True:
           neutron.create_network(body=json)
           print '\nnetwork-' + str(i) + ' created'
           break

        pool = Pool(processes=5)
        os.system("neutron quota-update --network 105")
        for i in range(1,5):
            pool.apply_async(create_network, (i, ))
        pool.close()
        pool.join()

    def test_cordvtn_for_create_network(self):
        network = {'name': self.network_name, 'admin_state_up': True}
        self.neutron.create_network({'network':network})
        log.info("Created network:{0}".format(self.network_name))

    def test_cordvtn_to_create_net_work_with_subnet(self):
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

    def test_cordvtn_subnet_limit(self):
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

    def test_cordvtn_floatingip_limit(self):
	while True:
	    floatingip = {"floating_network_id": self.floating_nw_id}
	    fip_info = self.neutron.create_floatingip({'floatingip':floatingip})
	    fip_id = fip_info['floatingip']['id']
	    log.info("Created Floating IP:{0}".format(fip_id))
	    self.fip_ids.append(fip_id)
	    if not self.quota_limit:
               break
	    self.quota_limit -= 1

    def test_cordvtn_basic_tenant(self):
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

    def test_cordvtn_removing_service_network(self):
        pass

    def test_cordvtn_web_application(self):
        pass

    def test_cordvtn_service_port(self):
        pass
