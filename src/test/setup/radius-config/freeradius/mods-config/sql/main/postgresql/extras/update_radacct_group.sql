
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


/*
 * $Id: 37f42a0b13515b09f9c7792e8a64b2a3b187e7a3 $
 *
 * OPTIONAL Postgresql trigger for FreeRADIUS
 *
 * This trigger updates fills in the groupname field (which doesnt come in Accounting packets)
 * by querying the radusergroup table.
 * This makes it easier to do group summary reports, however note that it does add some extra
 * database load to 50% of your SQL accounting queries. If you dont care about group summary
 * reports then you dont need to install this.
 *
 */


CREATE OR REPLACE FUNCTION upd_radgroups() RETURNS trigger AS'

DECLARE
	v_groupname varchar;

BEGIN
	SELECT INTO v_groupname GroupName FROM radusergroup WHERE CalledStationId = NEW.CalledStationId AND UserName = NEW.UserName;
	IF FOUND THEN
		UPDATE radacct SET GroupName = v_groupname WHERE RadAcctId = NEW.RadAcctId;
	END IF;

	RETURN NEW;
END

'LANGUAGE plpgsql;


DROP TRIGGER upd_radgroups ON radacct;

CREATE TRIGGER upd_radgroups AFTER INSERT ON radacct
    FOR EACH ROW EXECUTE PROCEDURE upd_radgroups();


