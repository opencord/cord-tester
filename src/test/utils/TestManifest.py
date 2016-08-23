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

class TestManifest(object):

    def __init__(self, manifest):
        self.manifest = manifest
        with open(self.manifest, 'r') as fd:
            data = json.load(fd)
        self.onos_ip = data.get('onos', None)
        self.radius_ip = data.get('radius', None)
        self.head_node = data.get('head_node', None)
