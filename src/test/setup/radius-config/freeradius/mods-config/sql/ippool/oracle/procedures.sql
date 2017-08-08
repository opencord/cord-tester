
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


CREATE OR REPLACE FUNCTION msqlippool(user varchar2, pool varchar2)
RETURN varchar2 IS

	PRAGMA AUTONOMOUS_TRANSACTION;
	ip_temp varchar2(20);
BEGIN

    -- If the user's pool is dynamic, get an ipaddress (oldest one) from the corresponding pool

    if pool = 'Dynamic' then
	select framedipaddress into ip_temp from (select framedipaddress from radippool where expiry_time < current_timestamp and pool_name = pool ORDER BY expiry_time) where rownum = 1;
	return (ip_temp);

    -- Else, then get the static ipaddress for that user from the corresponding pool

    else
	select framedipaddress into ip_temp from radippool where username = user and pool_name = pool;
	return (ip_temp);
    end if;

exception

 -- This block is executed if there's no free ipaddresses or no static ip assigned to the user

 when NO_DATA_FOUND then
	if pool = 'Dynamic' then
		return(''); -- so sqlippool can log it on radius.log
	end if;

	-- Else, grabs a free IP from the static pool and saves it in radippool so the user will always get the same IP the next time

	select framedipaddress into ip_temp from (select framedipaddress from radippool where expiry_time < current_timestamp and username is null and pool_name = pool) where rownum = 1;
	UPDATE radippool SET username = user where framedipaddress = ip_temp;
	commit;
	return (ip_temp);

 when others
  then return('Oracle Exception');

END;
/
