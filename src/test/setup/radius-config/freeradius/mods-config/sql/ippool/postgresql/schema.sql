
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


--
-- Table structure for table 'radippool'
--

CREATE TABLE radippool (
	id			BIGSERIAL PRIMARY KEY,
	pool_name		varchar(64) NOT NULL,
	FramedIPAddress		INET NOT NULL,
	NASIPAddress		VARCHAR(16) NOT NULL default '',
	pool_key		VARCHAR(64) NOT NULL default 0,
	CalledStationId		VARCHAR(64),
	CallingStationId	text NOT NULL default ''::text,
	expiry_time		TIMESTAMP(0) without time zone NOT NULL default 'now'::timestamp(0),
	username		text DEFAULT ''::text
);

CREATE INDEX radippool_poolname_expire ON radippool USING btree (pool_name, expiry_time);
CREATE INDEX radippool_framedipaddress ON radippool USING btree (framedipaddress);
CREATE INDEX radippool_nasip_poolkey_ipaddress ON radippool USING btree (nasipaddress, pool_key, framedipaddress);
