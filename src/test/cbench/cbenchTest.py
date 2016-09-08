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
import os
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from OnosCtrl import OnosCtrl
from scapy.all import *
log.setLevel('INFO')

class cbench_exchange(unittest.TestCase):

    igmp_app_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../apps',
                                 'ciena-cordigmp-cbench-1.0-SNAPSHOT.oar')
    igmp_app_file_default = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../apps',
                                         'ciena-cordigmp-2.0-SNAPSHOT.oar')
    igmp_app = 'org.ciena.cordigmp'
    switch_script = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup', 'of-bridge.sh')
    switch = 'br-int'
    ctlr_ip = os.getenv('ONOS_CONTROLLER_IP', 'localhost')
    ctlr_port = '6653'
    cbench = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cbench')
    cbench_igmp_options = '-g -D 3000 -w 10 -c {} -p {}'.format(ctlr_ip, ctlr_port)
    CBENCH_TIMEOUT = 60

    @classmethod
    def setUpClass(cls):
        cls.stop_switch()
        cls.install_app()

    @classmethod
    def tearDownClass(cls):
        cls.install_app_default()
        cls.start_switch()

    @classmethod
    def install_app(cls):
        OnosCtrl.uninstall_app(cls.igmp_app)
        time.sleep(2)
        OnosCtrl.install_app(cls.igmp_app_file)
        time.sleep(3)

    @classmethod
    def install_app_default(cls):
        OnosCtrl.uninstall_app(cls.igmp_app)
        time.sleep(2)
        OnosCtrl.install_app(cls.igmp_app_file_default)

    @classmethod
    def stop_switch(cls):
        cmd = 'service openvswitch-switch stop'
        log.info('Stopping switch before running cbench fakeswitch tests')
        os.system(cmd)
        time.sleep(1)

    @classmethod
    def start_switch(cls):
        cmd = '{} {}'.format(cls.switch_script, cls.switch)
        log.info('Starting back switch with command: \"%s\"', cmd)
        os.system(cmd)
        time.sleep(3)
        
    @deferred(CBENCH_TIMEOUT)
    def test_cbench_igmp(self):
        df = defer.Deferred()
        def cbench_igmp_join_leave_loop(df):
            cmd = '{} {} -l 20 -s 1 -m 1000'.format(self.cbench, self.cbench_igmp_options)
            os.system(cmd)
            df.callback(0)
        reactor.callLater(0, cbench_igmp_join_leave_loop, df)
        return df
