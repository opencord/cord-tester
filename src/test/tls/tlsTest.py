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
from EapTLS import TLSAuthTest
from OnosCtrl import OnosCtrl

class eap_auth_exchange(unittest.TestCase):

      app = 'org.onosproject.aaa'

      def setUp(self):
            self.onos_ctrl = OnosCtrl(self.app)
            self.onos_aaa_config()

      def onos_aaa_config(self):
            aaa_dict = {'apps' : { 'org.onosproject.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password', 
                                                                   'radiusIp': '172.17.0.2' } } } }
            radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
            aaa_dict['apps']['org.onosproject.aaa']['AAA']['radiusIp'] = radius_ip
            self.onos_ctrl.activate()
            time.sleep(2)
            self.onos_load_config(aaa_dict)

      def onos_load_config(self, config):
            status, code = OnosCtrl.config(config)
            if status is False:
                  log.info('Configure request for AAA returned status %d' %code)
                  assert_equal(status, True)
            time.sleep(3)
            
      def test_eap_tls(self):
          tls = TLSAuthTest()
          tls.runTest()

if __name__ == '__main__':
    t = TLSAuthTest()
    t.runTest()
    
