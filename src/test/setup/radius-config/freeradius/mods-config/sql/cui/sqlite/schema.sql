
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


CREATE TABLE `cui` (
  `clientipaddress` varchar(46) NOT NULL default '',
  `callingstationid` varchar(50) NOT NULL default '',
  `username` varchar(64) NOT NULL default '',
  `cui` varchar(32) NOT NULL default '',
  `creationdate` timestamp NOT NULL default CURRENT_TIMESTAMP,
  `lastaccounting` timestamp NOT NULL default '0000-00-00 00:00:00',
  PRIMARY KEY  (`username`,`clientipaddress`,`callingstationid`)
);
