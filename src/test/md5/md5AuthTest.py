import unittest
import os,sys
CORD_TEST_UTILS = 'utils'
test_root = os.getenv('CORD_TEST_ROOT') or './'
sys.path.append(test_root + CORD_TEST_UTILS)
from EapMD5 import MD5AuthTest

class eap_auth_exchange(unittest.TestCase):
      def test_eap_md5(self):
          t = MD5AuthTest()
          t.runTest()
      def test_eap_md5_wrg_password(self):
          t =  MD5AuthTest()
          t._wrong_password()
          t.runTest()

if __name__ == '__main__':
          t =  MD5AuthTest()
          t.runTest()
          ####### Start the EAP-MD5 Negative testcase 
          t._wrong_password()
          t.runTest()

