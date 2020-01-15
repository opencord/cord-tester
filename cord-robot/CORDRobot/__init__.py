# Copyright 2017-present Open Networking Foundation
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

from __future__ import absolute_import

import os

from .CORDDictUtils import CORDDictUtils
from .restApi import restApi
from .testCaseUtils import TestCaseUtils


# return the library version
def _version_():
    with open(os.path.join(os.path.dirname(__file__), "VERSION")) as f:
        return f.read().strip()


# Inherit all the other sub-classes
class CORDRobot(CORDDictUtils, restApi, TestCaseUtils):

    ROBOT_LIBRARY_SCOPE = "GLOBAL"

    def cr_version(self):
        return _version_()
