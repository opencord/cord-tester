import unittest
import os,sys
CORD_TEST_UTILS = 'utils'
test_root = os.getenv('CORD_TEST_ROOT') or './'
sys.path.append(test_root + CORD_TEST_UTILS)
from Dns_new import DNSTest
class dns_exchange(unittest.TestCase):
     
      def test_dns_ptr_query(self):
          obj=DNSTest()
          t = obj._dns_snd_ptr()

      def test_dns_A(self):
          obj=DNSTest()
          t = obj._dns_snd_rec()
      def test_dns_invalid_url(self):
          obj=DNSTest()
          t = obj._dns_snd_inv()

      def test_dns_invalid_reverse_query(self):
          obj=DNSTest()
          t = obj._dns_snd_ptr_inv()
      def test_dns_AAAA(self):
          obj=DNSTest()
          t = obj._dns_snd_AAAA()

      def test_dns_CNAME(self):
          obj=DNSTest()
          t = obj._dns_snd_CNAME()

      def test_dns_ptr_query(self):
          obj=DNSTest()
          t = obj._dns_snd_ptr()




if __name__ == '__main__':
          t = DNSTest()
          t._dns_snd_ptr()
          t._dns_snd_rec()
          t._dns_snd_inv()
          t._dns_snd_ptr_inv()
          t._dns_snd_AAAA()
          t._dns_snd_CNAME()
          t._dns_snd_ptr()




