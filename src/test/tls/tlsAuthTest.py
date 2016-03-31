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
    
