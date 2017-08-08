
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


CREATE TABLE radippool (
	id                      int PRIMARY KEY,
	pool_name               varchar(30) NOT NULL,
	framedipaddress         varchar(30) NOT NULL,
	nasipaddress            varchar(30) NOT NULL DEFAULT '',
	pool_key                varchar(64) NOT NULL DEFAULT '',
	calledstationid         varchar(64),
	callingstationid        varchar(64) NOT NULL DEFAULT '',
	expiry_time             timestamp DEFAULT NULL,
	username                varchar(100)
);
 
-- Example of how to put IPs in the pool
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (1, 'local', '192.168.5.10');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (2, 'local', '192.168.5.11');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (3, 'local', '192.168.5.12');
-- INSERT INTO radippool (id, pool_name, framedipaddress) VALUES (4, 'local', '192.168.5.13');

