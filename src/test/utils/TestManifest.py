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
import json
import os
import shutil
import platform
from CordTestServer import CORD_TEST_HOST, CORD_TEST_PORT

class TestManifest(object):

    def __init__(self, manifest = None, args = None):
        self.manifest = manifest
        if args is not None and manifest is None:
            self.onos_ip = None
            self.radius_ip = None
            self.head_node = platform.node()
            self.log_level = args.log_level.upper()
            self.onos_instances = args.onos_instances
            self.async_mode = args.async_mode
            self.shared_volume = args.shared_volume
            self.olt = args.olt
            self.start_switch = args.start_switch
            self.image_prefix = args.prefix
            self.onos_image = args.onos
            self.iterations = None
            self.server = '{}:{}'.format(CORD_TEST_HOST, CORD_TEST_PORT)
        else:
            with open(self.manifest, 'r') as fd:
                data = json.load(fd)
            self.onos_ip = data.get('onos', None)
            self.radius_ip = data.get('radius', None)
            self.head_node = data.get('head_node', platform.node())
            self.log_level = data.get('log_level', 'INFO').upper()
            self.onos_instances = data.get('onos_instances', 1)
            self.shared_volume = data.get('shared_volume', True)
            self.async_mode = True if self.onos_instances > 1 else False
            self.olt = data.get('olt', True)
            self.start_switch = data.get('start_switch', self.olt)
            self.image_prefix = data.get('image_prefix', '')
            self.onos_image = data.get('onos_image', 'onosproject/onos:latest')
            self.server = data.get('test_server', '{}:{}'.format(CORD_TEST_HOST, CORD_TEST_PORT))
            self.iterations = data.get('iterations', None)
