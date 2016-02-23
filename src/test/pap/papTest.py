import unittest
import os,sys
CORD_TEST_UTILS = 'utils'
test_root = os.getenv('CORD_TEST_ROOT') or './'
sys.path.append(test_root + CORD_TEST_UTILS)
from EapPAP import PAPAuthTest

class eap_auth_exchange(unittest.TestCase):
      def test_eap_pap(self):
          pap = PAPAuthTest()
          pap.runTest()

if __name__ == '__main__':
    t = PAPAuthTest()
    t.runTest()
    
