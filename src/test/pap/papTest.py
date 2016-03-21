import unittest
import os,sys
from nose.tools import assert_equal
from EapPAP import PAPAuthTest

class eap_auth_exchange(unittest.TestCase):
      def test_eap_pap(self):
          pap = PAPAuthTest()
          pap.runTest()

if __name__ == '__main__':
    t = PAPAuthTest()
    t.runTest()
    
