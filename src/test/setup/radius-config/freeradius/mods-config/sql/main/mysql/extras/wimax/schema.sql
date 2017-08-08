
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
# WiMAX Table structure for table 'wimax',
# which replaces the "radpostauth" table.
#

CREATE TABLE wimax (
  id int(11) NOT NULL auto_increment,
  username varchar(64) NOT NULL default '',
  authdate timestamp NOT NULL,
  spi varchar(16) NOT NULL default '',
  mipkey varchar(400) NOT NULL default '',
  lifetime int(12) default NULL,
  PRIMARY KEY  (id),
  KEY username (username),
  KEY spi (spi)
) ;
