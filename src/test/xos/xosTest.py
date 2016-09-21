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
import subprocess
from docker import Client
from itertools import chain
from nose.tools import *
from scapy.all import *
from CordContainer import *
import threading
import time
import os
import json
import pexpect
log.setLevel('INFO')


flatten = lambda l: chain.from_iterable(l)

class xos_exchange(unittest.TestCase):

    dckr = Client()
    test_path = os.path.dirname(os.path.realpath(__file__))
    XOS_BASE_CONTAINER_IMAGE = 'xosproject/xos-base:latest'
    XOS_BASE_CONTAINER_NAME = 'xos-base'
    XOS_BASE_CONTAINER_PORTS = [8000]
    XOS_SYN_OPENSTACK_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-openstack'
    XOS_SYN_OPENSTACK_CONTAINER_NAME = 'xos-synchronizer-openstack'
    XOS_SYN_OPENSTACK_CONTAINER_PORTS = [8000]
    XOS_POSTGRESQL_CONTAINER_IMAGE = 'ubuntu:14.04'
    XOS_POSTGRESQL_CONTAINER_NAME = 'xos-postgresql'
    XOS_POSTGRESQL_CONTAINER_PORTS = [5432]
    XOS_SYNDICATE_MS_CONTAINER_IMAGE = 'ubuntu:14.04.4'
    XOS_SYNDICATE_MS_CONTAINER_NAME = 'syndicate-ms'
    XOS_SYNDICATE_MS_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vtr'
    XOS_SYNCHRONIZER_VTR_CONTAINER_NAME = 'xos-synchronizer-vtr'
    XOS_SYNCHRONIZER_VTR_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vsg'
    XOS_SYNCHRONIZER_VSG_CONTAINER_NAME = 'xos-synchronizer-vsg'
    XOS_SYNCHRONIZER_VSG_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-onos'
    XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME = 'xos-synchronizer-onos'
    XOS_SYNCHRONIZER_ONOS_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-fabric'
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME = 'xos-synchronizer-fabric'
    XOS_SYNCHRONIZER_FABRIC_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-vtn'
    XOS_SYNCHRONIZER_VTN_CONTAINER_NAME = 'xos-synchronizer-vtn'
    XOS_SYNCHRONIZER_VTN_CONTAINER_PORTS = [8080]
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE = 'xosproject/xos-synchronizer-onboarding'
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME = 'xos-synchronizer-onboarding'
    XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_PORTS = [8080]

    def setUp(self):
        ''' Activate the XOS containers'''
        self.maxDiff = None ##for assert_equal compare outputs on failure

    def tearDown(self):
        '''Deactivate the xos containers'''
        log.info('Tear down setup')
        self.CURRENT_PORT_NUM = 4

    def exists(self, name):
        return '/{0}'.format(name) in list(flatten(n['Names'] for n in self.dckr.containers()))


    def img_exists(self, image):
        cnt = filter(lambda c: c['Image'] == image, self.dckr.containers())
        return image in [ctn['RepoTags'][0] if ctn['RepoTags'] else '' for ctn in self.dckr.images()]

    def xos_containers_check(self, name, image):
           if self.exists(name) != True:
              if name == self.XOS_BASE_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosBase = Xos_base(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYN_OPENSTACK_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_openstack(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_POSTGRESQL_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosPostgresql = Xos_postgresql(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNDICATE_MS_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSyndicateMs = Xos_syndicate_ms(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_vtr(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_vsg(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_onos(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_fabric(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_vtn(prefix = Container.IMAGE_PREFIX, update = False)
              if name == self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME:
                 log.info('%s container is not running, hence build and run it, waiting until container is up' %name)
                 xosSynOpenstack = Xos_sync_onboarding(prefix = Container.IMAGE_PREFIX, update = False)
              if self.img_exists(image) != True:
                 log.info('%s container image is not built on host, its a github issue' %name)
                 assert_equal(False, True)
              if self.exists(name) != True:
                 log.info('%s container image is build on host, but its not up and running' %name)
                 assert_equal(False, True)

    def container_status(self, image, name):
        ''' This function is checking that container is up and running'''
        self.xos_containers_check(name, image)
        container_info = self.dckr.containers(filters ={'name':name, 'status':'running'})
        log.info('Xos container info= %s' %container_info)

        if not container_info:
           ## forcely failing test case
           log.info('%s container is not running, container info %s' %(name,container_info))
           assert_equal(False, True)
        else:
           container_status = container_info[0]['Status']
           log.info('Xos container status= %s' %container_status)
           assert_equal(container_status.split(' ')[0], 'Up')
           return container_info

    def container_ping(self, image, name):
        ''' This function is checking that container is able to ping to its ip '''
        container_info = self.container_status(image= image, name= name)
        container_ip = container_info[0]['NetworkSettings']['Networks']['bridge']['IPAddress']
        ping_status = os.system('ping {} -c 3'.format(container_ip))
        if ping_status != 0:
           log.info('%s container is not able to reach and ip is not ping, response %s = '%(name,ping_status))
           assert_equal(ping_status, 0)
        log.info('%s container is able to reach and ip is ping, response = %s'%(name,ping_status))
        assert_equal(ping_status, 0)

    def container_listening_ports_info(self, image, name, ports_list):
        ''' This function is checking that container ports are as excpeted '''
        container_public_ports = []
        container_info = self.container_status(image= image, name= name)
        container_ports = container_info[0]['Ports']
        container_public_ports.append(container_ports[0]['PublicPort'])
        log.info('%s container is listening on these ports = %s'%(name,container_ports))
        log.info('%s container is listening on these public ports = %s'%(name,container_public_ports))
        for n in range(0,len(ports_list)):
            port = ports_list[n]
            if port in container_public_ports:
               assert_equal(True, True)
            else:
               log.info('%s container is not listening on %s port which is not expected' %(name,n))
               assert_equal(False, True)

    def container_stop_start(self):
        ''' This function is checking container is stop and running if we start again'''

    def test_xos_base_container_status(self):
        self.container_status(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME)

    def test_xos_base_container_ping(self):
        self.container_ping(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME)

    def test_xos_base_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_BASE_CONTAINER_IMAGE, name = self.XOS_BASE_CONTAINER_NAME,
                                             ports_list = self.XOS_BASE_CONTAINER_PORTS)

    def test_xos_sync_openstack_container_status(self):
        self.container_status(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE, name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME)

    def test_xos_sync_openstack_container_ping(self):
        self.container_ping(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE, name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME)

    def test_xos_sync_openstack_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYN_OPENSTACK_CONTAINER_IMAGE,
                                            name = self.XOS_SYN_OPENSTACK_CONTAINER_NAME,
                                            ports_list = self.XOS_SYN_OPENSTACK_CONTAINER_PORTS)

    def test_xos_postgresql_container_status(self):
        self.container_status(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE, name = self.XOS_POSTGRESQL_CONTAINER_NAME)

    def test_xos_postgresql_container_ping(self):
        self.container_ping(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE, name = self.XOS_POSTGRESQL_CONTAINER_NAME)

    def test_xos_postgresql_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_POSTGRESQL_CONTAINER_IMAGE,
                                            name = self.XOS_POSTGRESQL_CONTAINER_NAME,
                                            ports_list = self.XOS_POSTGRESQL_CONTAINER_PORTS)

    def test_xos_syndicate_ms_container_status(self):
        self.container_status(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE, name = self.XOS_SYNDICATE_MS_CONTAINER_NAME)

    def test_xos_syndicate_ms_container_ping(self):
        self.container_ping(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE, name = self.XOS_SYNDICATE_MS_CONTAINER_NAME)

    def test_xos_syndicate_ms_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNDICATE_MS_CONTAINER_IMAGE,
                                            name = self.XOS_SYNDICATE_MS_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNDICATE_MS_CONTAINER_PORTS)

    def test_xos_sync_vtr_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME)

    def test_xos_sync_vtr_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME)

    def test_xos_sync_vtr_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VTR_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VTR_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VTR_CONTAINER_PORTS)
    def test_xos_sync_vsg_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME)

    def test_xos_sync_vsg_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME)

    def test_xos_sync_vsg_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VSG_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VSG_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VSG_CONTAINER_PORTS)
    def test_xos_sync_onos_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME)

    def test_xos_sync_onos_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME)

    def test_xos_sync_onos_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_ONOS_CONTAINER_PORTS)
    def test_xos_sync_fabric_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME)

    def test_xos_sync_fabric_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME)

    def test_xos_sync_fabric_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_FABRIC_CONTAINER_PORTS)
    def test_xos_sync_vtn_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME)

    def test_xos_sync_vtn_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME)

    def test_xos_sync_vtn_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_VTN_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_VTN_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_VTN_CONTAINER_PORTS)
    def test_xos_sync_onboarding_container_status(self):
        self.container_status(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE)

    def test_xos_sync_onboarding_container_ping(self):
        self.container_ping(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE, name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE)

    def test_xos_sync_onboarding_container_listening_ports(self):
        self.container_listening_ports_info(image = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_IMAGE,
                                            name = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_NAME,
                                            ports_list = self.XOS_SYNCHRONIZER_ONBOARDING_CONTAINER_PORTS)
