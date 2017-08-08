
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
import os,sys
from utilities import Utilities, utilities
from CordTestUtils import log_test as log

#log.setLevel('INFO')
class MAIN(object):
    def __init__(self):
        global utilities
        self.log = log
        self.logdir = os.getenv('HOME')
        self.logHeader = ''
        self.utilities = utilities
        self.TRUE = True
        self.FALSE = False
        self.EXPERIMENTAL_MODE = self.FALSE

    def cleanup(self): pass

    def exit(self): pass

main = MAIN()
