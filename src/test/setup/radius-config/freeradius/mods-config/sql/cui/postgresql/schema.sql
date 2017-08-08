
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


CREATE TABLE cui (
  clientipaddress INET NOT NULL DEFAULT '0.0.0.0',
  callingstationid varchar(50) NOT NULL DEFAULT '',
  username varchar(64) NOT NULL DEFAULT '',
  cui varchar(32) NOT NULL DEFAULT '',
  creationdate TIMESTAMP with time zone NOT NULL default 'now()',
  lastaccounting TIMESTAMP with time zone NOT NULL default '-infinity'::timestamp,
  PRIMARY KEY  (username, clientipaddress, callingstationid)
);

CREATE RULE postauth_query AS ON INSERT TO cui
	WHERE EXISTS(SELECT 1 FROM cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid))
	DO INSTEAD UPDATE cui SET lastaccounting ='-infinity'::timestamp with time zone, cui=NEW.cui WHERE (username, clientipaddress, callingstationid)=(NEW.username, NEW.clientipaddress, NEW.callingstationid);

