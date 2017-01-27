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
import time
import os, subprocess
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from OnosCtrl import OnosCtrl
from scapy.all import *
from CordContainer import *
from docker import Client
import json
import requests
log.setLevel('INFO')

class monitoring_exchange(unittest.TestCase):

    controllers = os.getenv('ONOS_CONTROLLER_IP', '').split(',')
    onosLogLevel = 'INFO'
    test_host_base = 'cord-tester1'#Hardcoded temporarily
    collectd_app = 'org.onosproject.cpman'
    testHostName = os.getenv('TEST_HOST', test_host_base)
    testLogLevel = os.getenv('LOG_LEVEL', onosLogLevel)
    stat_optionList = os.getenv('USER_OPTIONS', '').split(',')
    serverOptionsList = os.getenv('EXTERNAL_SERVER_OPTIONS', None)
    CBENCH_TIMEOUT = 60

    @classmethod
    def setUpClass(cls):
        onos_ctrl = OnosCtrl('org.onosproject.cpman')
        status, _ = onos_ctrl.activate()

    @classmethod
    def tearDownClass(cls):
        onos_ctrl = OnosCtrl('org.onosproject.cpman')
        status, _ = onos_ctrl.deactivate()

    @classmethod
    def stat_option(cls, stats = None, serverDetails = None):
        # each stats option we can do some specific functions
        if stats is None:
           stats = cls.stat_optionList
        if serverDetails is None:
           serverDetails = cls.serverOptionsList
        stats_choice = 'COLLECTD'
        test_name = cls.testHostName
        test_image = 'cord-test/nose'
        if stats_choice in stats:
           onos_ctrl = OnosCtrl('org.onosproject.cpman')
           status, _ = onos_ctrl.activate()
           if serverDetails is '':
              pass
           elif serverDetails in 'NEW':
                test_image = 'cord-test/exserver'
                test_name ='cord-collectd'
           else:
               pass
               ## TO-DO for already up and running server, install collectd agent etc...
           cls.start_collectd_agent_in_server(name = test_name, image = test_image)
        return


    @classmethod
    def collectd_agent_metrics(cls,controller=None, auth =None, url = None):
        '''This function is getting a rules from ONOS with json formate'''
        if url:
           resp = requests.get(url, auth = auth)
           log.info('CollectD agent has provided metrics via ONOS controller, \nurl = %s \nand stats = %s \nResponse = %s ' %(url,resp.json(),resp.ok))
           assert_equal(resp.ok, True)
        return resp


    @classmethod
    def start_collectd_agent_in_server(cls, name = None, image = None):
        container_cmd_exec = Container(name = name, image = image)
        tty = False
        dckr = Client()
        cmd =  'sudo /etc/init.d/collectd start'
        i = container_cmd_exec.execute(cmd = cmd, tty= tty, stream = True, shell = False)
        return i

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_installation(self):
        df = defer.Deferred()
        def collectd_sample(df):
            cmd = 'sudo /etc/init.d/collectd start'
            output = subprocess.check_output(cmd,shell= True)
            if 'Starting statistics collectio' in output:
               log.info('Collectd is installed properly')
               pass
            else:
               log.info('Collectd is not installed properly')
               assert_equal(False, True)
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_plugin_and_onos_installation(self):
        df = defer.Deferred()
        def collectd_sample(df):
            cmd = 'ls'
            output = subprocess.check_output(cmd,shell= True)
            if 'write_onos' in output:
               log.info('Collectd is installed properly and plugin happend to ONOS')
               pass
            else:
               log.info('Collectd is not installed properly and no plugin happend to ONOS')
               assert_equal(False, True)
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_cpu_stats(self):
        df = defer.Deferred()
        def collectd_sample(df):
            self.stat_option()
            for controller in self.controllers:
               if not controller:
                  continue
            url_cpu_stats =  'http://%s:8181/onos/cpman/controlmetrics/cpu_metrics'%(controller)
            auth = ('karaf', 'karaf')
            self.collectd_agent_metrics(controller, auth, url = url_cpu_stats)
            log.info('Successfully CPU metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_mem_stats(self):
        df = defer.Deferred()
        def collectd_sample(df):
            self.stat_option()
            for controller in self.controllers:
               if not controller:
                  continue
            url_mem_stats =  'http://%s:8181/onos/cpman/controlmetrics/memory_metrics'%(controller)
            auth = ('karaf', 'karaf')
            self.collectd_agent_metrics(controller, auth, url = url_mem_stats)
            log.info('Successfully memory metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_control_metrics_messages(self):
        df = defer.Deferred()
        def collectd_sample(df):
            self.stat_option()
            for controller in self.controllers:
               if not controller:
                  continue
            url_messages_stats =  'http://%s:8181/onos/cpman/controlmetrics/messages'%(controller)
            auth = ('karaf', 'karaf')
            self.collectd_agent_metrics(controller, auth, url = url_messages_stats)
            log.info('Successfully messages are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_network_metrics_stats(self):
        df = defer.Deferred()
        def collectd_sample(df):
            self.stat_option()
            for controller in self.controllers:
               if not controller:
                  continue
            url_network_stats =  'http://%s:8181/onos/cpman/controlmetrics/network_metrics'%(controller)
            auth = ('karaf', 'karaf')
            self.collectd_agent_metrics(controller, auth, url = url_network_stats)
            log.info('Successfully network metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_network_metrics_stats(self):
        df = defer.Deferred()
        def collectd_sample(df):
            self.stat_option()
            for controller in self.controllers:
               if not controller:
                  continue
            url_network_stats =  'http://%s:8181/onos/cpman/controlmetrics/disk_metrics'%(controller)
            auth = ('karaf', 'karaf')
            self.collectd_agent_metrics(controller, auth, url = url_network_stats)
            log.info('Successfully disk metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_for_installing_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               test_image = 'cord-test/exserver'
               test_name ='cord-collectd'
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               ## starting collectd agent on new container
               cmd = 'sudo /etc/init.d/collectd start'
               output = self.start_collectd_agent_in_server(name = test_name, image = test_image)
               if output == 0:
                  log.info('Collectd is installed properly on new container')
                  pass
               else:
                  log.info('Collectd is not installed properly on new container')
                  assert_equal(False, True)
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_for_cpu_metrics_on_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               self.stat_option()
               for controller in self.controllers:
                   if not controller:
                      continue
               url_cpu_stats =  'http://%s:8181/onos/cpman/controlmetrics/cpu_metrics'%(controller)
               auth = ('karaf', 'karaf')
               self.collectd_agent_metrics(controller, auth, url = url_cpu_stats)
               log.info('Successfully CPU metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_memory_metrics_on_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               self.stat_option()
               for controller in self.controllers:
                   if not controller:
                      continue
               url_mem_stats =  'http://%s:8181/onos/cpman/controlmetrics/memory_metrics'%(controller)
               auth = ('karaf', 'karaf')
               self.collectd_agent_metrics(controller, auth, url = url_mem_stats)
               log.info('Successfully memory metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_get_messages_on_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               self.stat_option()
               for controller in self.controllers:
                   if not controller:
                      continue
               url_messages_stats =  'http://%s:8181/onos/cpman/controlmetrics/messages'%(controller)
               auth = ('karaf', 'karaf')
               self.collectd_agent_metrics(controller, auth, url = url_messages_stats)
               log.info('Successfully messages metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_network_metrics_on_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               self.stat_option()
               for controller in self.controllers:
                   if not controller:
                      continue
               url_network_stats =  'http://%s:8181/onos/cpman/controlmetrics/network_metrics'%(controller)
               auth = ('karaf', 'karaf')
               self.collectd_agent_metrics(controller, auth, url = url_network_stats)
               log.info('Successfully network metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df

    @deferred(CBENCH_TIMEOUT)
    def test_stats_with_collectd_disk_metrics_on_new_container(self):
        df = defer.Deferred()
        def collectd_sample(df):
            if 'NEW' in self.serverOptionsList:
               ## stopping collectd agent on test container if any
               cmd = 'sudo /etc/init.d/collectd stop'
               output = os.system(cmd)
               self.stat_option()
               for controller in self.controllers:
                   if not controller:
                      continue
               url_disk_stats =  'http://%s:8181/onos/cpman/controlmetrics/disk_metrics'%(controller)
               auth = ('karaf', 'karaf')
               self.collectd_agent_metrics(controller, auth, url = url_disk_stats)
               log.info('Successfully network metrics are retained by the stats')
            df.callback(0)
        reactor.callLater(0, collectd_sample, df)
        return df
