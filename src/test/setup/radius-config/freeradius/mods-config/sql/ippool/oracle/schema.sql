
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
	id                      INT PRIMARY KEY,
	pool_name               VARCHAR(30) NOT NULL,
	framedipaddress         VARCHAR(30) NOT NULL,
	nasipaddress            VARCHAR(30) NOT NULL,
	pool_key                INT NOT NULL,
	CalledStationId         VARCHAR(64),
	CallingStationId        VARCHAR(64) NOT NULL,
	expiry_time             timestamp(0) NOT NULL,
	username                VARCHAR(100)
);

CREATE INDEX radippool_poolname_ipaadr ON radippool (pool_name, framedipaddress);
CREATE INDEX radippool_poolname_expire ON radippool (pool_name, expiry_time);
CREATE INDEX radippool_nasipaddr_key ON radippool (nasipaddress, pool_key);
CREATE INDEX radippool_nasipaddr_calling ON radippool (nasipaddress, callingstationid);

CREATE SEQUENCE radippool_seq START WITH 1 INCREMENT BY 1;

CREATE OR REPLACE TRIGGER radippool_serialnumber
	BEFORE INSERT OR UPDATE OF id ON radippool
	FOR EACH ROW
	BEGIN
		if ( :new.id = 0 or :new.id is null ) then
			SELECT radippool_seq.nextval into :new.id from dual;
		end if;
	END;
/
