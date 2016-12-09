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
import subprocess
from nose.tools import *
from onosclidriver import OnosCliDriver
from CordContainer import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from OnosCtrl import OnosCtrl
from scapy.all import *
log.setLevel('INFO')

class iperf_exchange(unittest.TestCase):

    switch_script = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../setup', 'of-bridge.sh')
    switch = 'br-int'
    ctlr_ip = os.getenv('ONOS_CONTROLLER_IP', 'localhost')
    ctlr_port = '6653'
    IPERF_TIMEOUT = 360
    app = 'org.onosproject.dhcp'

    @classmethod
    def setUpClass(cls):
        #cls.stop_switch()
        #cls.install_app()
        cmd = "apt-get install iperf"
        os.system(cmd)
        time.sleep(40)

    @classmethod
    def tearDownClass(cls):pass
        #cls.onos_ctrl.deactivate()

    @classmethod
    def install_app(cls):
        OnosCtrl.uninstall_app(cls.igmp_app)
        time.sleep(2)
        OnosCtrl.install_app(cls.igmp_app_file)
        time.sleep(3)

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

    @classmethod
    def iperf_tool_cmd_execution(cls,cmd = " "):
        log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))

        try:
#           status = os.system(cmd)
            status = subprocess.Popen(cmd, shell=True)
            time.sleep(90)
            pid = status.pid
            log.info('Subprocess status = {}'.format(status))
            log.info('Subprocess task id on host = {}'.format(pid))
            status.terminate()
        except Exception:
            status.terminate()
            main.log.exception( self.name + ": Uncaught exception!" )
            main.cleanup()
            main.exit()

    @deferred(IPERF_TIMEOUT)
    def test_tcp_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            os.system(cmd)
            self.onos_ctrl = OnosCtrl(self.app)
            status, _ = self.onos_ctrl.activate()
            assert_equal(status, True)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_udp_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -u -t 20 -P 1 -i 1'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            self.onos_ctrl = OnosCtrl(self.app)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_tcp_window_of_40k_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -w 40k'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df


    @deferred(IPERF_TIMEOUT)
    def test_tcp_window_of_120k_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -w 120k'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df


    @deferred(IPERF_TIMEOUT)
    def test_tcp_window_of_520k_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -w 520k'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_multiple_tcp_sessions_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 5 -P 2 -i 1'
            self.iperf_tool_cmd_execution(cmd = cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_multiple_udp_sessions_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -u -t 5 -P 2 -i 1'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df


    @deferred(IPERF_TIMEOUT)
    def test_tcp_mss_with_90Bytes_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -m -M 90'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_tcp_mss_with_1490Bytes_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -m -M 1490'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

    @deferred(IPERF_TIMEOUT)
    def test_tcp_mss_with_9000Bytes_for_max_throughput_using_iperf(self):
        df = defer.Deferred()
        def iperf_network_test(df):
            cmd = 'iperf -c 172.17.0.2 -p 6653 -t 20 -P 1 -i 1 -m -M 9000'
            log.info('Test Controller by executing a iperf tool command on host = {}'.format(cmd))
            status = os.system(cmd)
            df.callback(0)
        reactor.callLater(0, iperf_network_test, df)
        return df

