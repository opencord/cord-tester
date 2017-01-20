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
import os
import sys
import glanceclient

from keystoneclient.v2_0 import client
from keystoneclient import utils
from novaclient import client as novaclient
from keystoneclient import client as keystoneclient
from neutronclient.neutron import client as neutronclient


def keystone_client_version():
    api_version = os.getenv('OS_IDENTITY_API_VERSION')
    if api_version is not None:
       log.info("Version is set in env as '%s'",
                    api_version)
       return api_version
    return SET_API_VERSION


def keystone_client(other_creds={}):
    sess = session(other_creds)
    return keystoneclient.Client(keystone_client_version(), session=sess)


def nova_client_version():
    api_version = os.getenv('OS_COMPUTE_API_VERSION')
    if api_version is not None:
        log.info("OS_COMPUTE_API_VERSION is set in env as '%s'",
                    api_version)
        return api_version
    return SET_API_VERSION


def nova_client(other_creds={}):
    sess = session(other_creds)
    return novaclient.Client(nova_client_version(), session=sess)


def neutron_client_version():
    api_version = os.getenv('OS_NETWORK_API_VERSION')
    if api_version is not None:
        log.info("OS_NETWORK_API_VERSION is set in env as '%s'",
                    api_version)
        return api_version
    return SET_API_VERSION


def neutron_client(other_creds={}):
    sess = session(other_creds)
    return neutronclient.Client(neutron_client_version(), session=sess)


def glance_client_version():
    api_version = os.getenv('OS_IMAGE_API_VERSION')
    if api_version is not None:
        log.info("OS_IMAGE_API_VERSION is set in env as '%s'", api_version)
        return api_version
    return SET_API_VERSION


def glance_client(other_creds={}):
    sess = session(other_creds)
    return glanceclient.Client(glance_client_version(), session=sess)

def network_list(neutron_client):
    network_list = neutron_client.list_networks()['networks']
    if len(network_list) == 0:
        return None
    else:
        return network_list


def router_list(neutron_client):
    router_list = neutron_client.list_routers()['routers']
    if len(router_list) == 0:
        return None
    else:
        return router_list


def port_list(neutron_client):
    port_list = neutron_client.list_ports()['ports']
    if len(port_list) == 0:
        return None
    else:
        return port_list


def network_id(neutron_client, network_name):
    networks = neutron_client.list_networks()['networks']
    id = ''
    for n in networks:
        if n['name'] == network_name:
            id = n['id']
            break
    return id


def subnet_id(neutron_client, subnet_name):
    subnets = neutron_client.list_subnets()['subnets']
    id = ''
    for s in subnets:
        if s['name'] == subnet_name:
            id = s['id']
            break
    return id


def router_id(neutron_client, router_name):
    routers = neutron_client.list_routers()['routers']
    id = ''
    for r in routers:
        if r['name'] == router_name:
            id = r['id']
            break
    return id


def private_net(neutron_client):
    networks = neutron_client.list_networks()['networks']
    if len(networks) == 0:
        return None
    for net in networks:
        if (net['router:external'] is False) and (net['shared'] is True):
            return net
    return None


def external_net(neutron_client):
    for network in neutron_client.list_networks()['networks']:
        if network['router:external']:
            return network['name']
    return None


def external_net_id(neutron_client):
    for network in neutron_client.list_networks()['networks']:
        if network['router:external']:
            return network['id']
    return None


def check_neutron_net(neutron_client, net_name):
    for network in neutron_client.list_networks()['networks']:
        if network['name'] == net_name:
            for subnet in network['subnets']:
                return True
    return False


def create_neutron_net(neutron_client, name):
    json_body = {'network': {'name': name,
                             'admin_state_up': True}}
    try:
        network = neutron_client.create_network(body=json_body)
        net_sett = network['network']
        return net_sett['id']
    except Exception, e:
        log.info("Error [create_neutron_net(neutron_client, '%s')]: %s"
                     % (name, e))
        return None


def create_neutron_subnet(neutron_client, name, cidr, net_id):
    json_body = {'subnets': [{'name': name, 'cidr': cidr,
                              'ip_version': 4, 'network_id': net_id}]}
    try:
        subnet = neutron_client.create_subnet(body=json_body)
        return subnet['subnets'][0]['id']
    except Exception, e:
        log.info("Error [create_neutron_subnet(neutron_client, '%s', "
                     "'%s', '%s')]: %s" % (name, cidr, net_id, e))
        return None


def create_neutron_router(neutron_client, name):
    json_body = {'router': {'name': name, 'admin_state_up': True}}
    try:
        router = neutron_client.create_router(json_body)
        return router['router']['id']
    except Exception, e:
        log.info("Error [create_neutron_router(neutron_client, '%s')]: %s"
                     % (name, e))
        return None


def create_neutron_port(neutron_client, name, network_id, ip):
    json_body = {'port': {
                 'admin_state_up': True,
                 'name': name,
                 'network_id': network_id,
                 'fixed_ips': [{"ip_address": ip}]
                 }}
    try:
        port = neutron_client.create_port(body=json_body)
        return port['port']['id']
    except Exception, e:
        log.info("Error [create_neutron_port(neutron_client, '%s', '%s', "
                     "'%s')]: %s" % (name, network_id, ip, e))
        return None


def update_neutron_net(neutron_client, network_id, shared=False):
    json_body = {'network': {'shared': shared}}
    try:
        neutron_client.update_network(network_id, body=json_body)
        return True
    except Exception, e:
        log.info("Error [update_neutron_net(neutron_client, '%s', '%s')]: "
                     "%s" % (network_id, str(shared), e))
        return False


def update_neutron_port(neutron_client, port_id, device_owner):
    json_body = {'port': {
                 'device_owner': device_owner,
                 }}
    try:
        port = neutron_client.update_port(port=port_id,
                                          body=json_body)
        return port['port']['id']
    except Exception, e:
        log.info("Error [update_neutron_port(neutron_client, '%s', '%s')]:"
                     " %s" % (port_id, device_owner, e))
        return None


def add_interface_router(neutron_client, router_id, subnet_id):
    json_body = {"subnet_id": subnet_id}
    try:
        neutron_client.add_interface_router(router=router_id, body=json_body)
        return True
    except Exception, e:
        log.info("Error [add_interface_router(neutron_client, '%s', "
                     "'%s')]: %s" % (router_id, subnet_id, e))
        return False


def add_gateway_router(neutron_client, router_id):
    ext_net_id = external_net_id(neutron_client)
    router_dict = {'network_id': ext_net_id}
    try:
        neutron_client.add_gateway_router(router_id, router_dict)
        return True
    except Exception, e:
        log.info("Error [add_gateway_router(neutron_client, '%s')]: %s"
                     % (router_id, e))
        return False


def delete_neutron_net(neutron_client, network_id):
    try:
        neutron_client.delete_network(network_id)
        return True
    except Exception, e:
        log.info("Error [delete_neutron_net(neutron_client, '%s')]: %s"
                     % (network_id, e))
        return False


def delete_neutron_subnet(neutron_client, subnet_id):
    try:
        neutron_client.delete_subnet(subnet_id)
        return True
    except Exception, e:
        log.info("Error [delete_neutron_subnet(neutron_client, '%s')]: %s"
                     % (subnet_id, e))
        return False


def delete_neutron_router(neutron_client, router_id):
    try:
        neutron_client.delete_router(router=router_id)
        return True
    except Exception, e:
        log.info("Error [delete_neutron_router(neutron_client, '%s')]: %s"
                     % (router_id, e))
        return False


def delete_neutron_port(neutron_client, port_id):
    try:
        neutron_client.delete_port(port_id)
        return True
    except Exception, e:
        log.info("Error [delete_neutron_port(neutron_client, '%s')]: %s"
                     % (port_id, e))
        return False


def remove_interface_router(neutron_client, router_id, subnet_id):
    json_body = {"subnet_id": subnet_id}
    try:
        neutron_client.remove_interface_router(router=router_id,
                                               body=json_body)
        return True
    except Exception, e:
        log.info("Error [remove_interface_router(neutron_client, '%s', "
                     "'%s')]: %s" % (router_id, subnet_id, e))
        return False


def remove_gateway_router(neutron_client, router_id):
    try:
        neutron_client.remove_gateway_router(router_id)
        return True
    except Exception, e:
        log.info("Error [remove_gateway_router(neutron_client, '%s')]: %s"
                     % (router_id, e))
        return False


def create_network_full(neutron_client,
                        net_name,
                        subnet_name,
                        router_name,
                        cidr):

    # Check if the network already exists
    network_id = network_id(neutron_client, net_name)
    subnet_id = subnet_id(neutron_client, subnet_name)
    router_id = router_id(neutron_client, router_name)

    if network_id != '' and subnet_id != '' and router_id != '':
        log.info("A network with name '%s' already exists..." % net_name)
    else:
        neutron_client.format = 'json'
        log.info('Creating neutron network %s...' % net_name)
        network_id = create_neutron_net(neutron_client, net_name)

        if not network_id:
            return False

        log.info("Network '%s' created successfully" % network_id)
        log.info('Creating Subnet....')
        subnet_id = create_neutron_subnet(neutron_client, subnet_name,
                                          cidr, network_id)
        if not subnet_id:
            return None

        log.info("Subnet '%s' created successfully" % subnet_id)
        log.info('Creating Router...')
        router_id = create_neutron_router(neutron_client, router_name)

        if not router_id:
            return None

        log.info("Router '%s' created successfully" % router_id)
        log.info('Adding router to subnet...')

        if not add_interface_router(neutron_client, router_id, subnet_id):
            return None

        log.info("Interface added successfully.")

        log.info('Adding gateway to router...')
        if not add_gateway_router(neutron_client, router_id):
            return None

        log.info("Gateway added successfully.")

    net_set = {'net_id': network_id,
                   'subnet_id': subnet_id,
                   'router_id': router_id}
    return net_set


def create_shared_network_full(net_name, subnt_name, router_name, subnet_cidr):
    neutron_client = neutron_client()

    net_set = create_network_full(neutron_client,
                                      net_name,
                                      subnt_name,
                                      router_name,
                                      subnet_cidr)
    if net_set:
        if not update_neutron_net(neutron_client,
                                  net_set['net_id'],
                                  shared=True):
            log.info("Failed to update network %s..." % net_name)
            return None
        else:
            log.info("Network '%s' is available..." % net_name)
    else:
        log.info("Network %s creation failed" % net_name)
        return None
    return net_set

