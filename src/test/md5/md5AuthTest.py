#!/usr/bin/env python
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
import os,sys
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

