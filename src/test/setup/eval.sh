#!/usr/bin/env bash
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

cord_tester="$(dirname $0)/cord-test.py"
if [ ! -f $cord_tester ]; then
  cord_tester="$HOME/cord-tester/src/test/setup/cord-test.py"
fi
echo "Building all cord-tester images."
$cord_tester build all
docker kill cord-onos || true
docker kill cord-quagga || true
docker kill cord-radius || true
function finish {
    $cord_tester cleanup --olt
    pkill -f cord-test
}
trap finish EXIT
$cord_tester setup --olt --start-switch
cnt=`docker ps -lq`
echo "Running TLS authentication test"
docker exec $cnt nosetests -v /root/test/src/test/tls/tlsTest.py:eap_auth_exchange.test_eap_tls
echo "Running DHCP relay request test"
docker exec $cnt nosetests -v /root/test/src/test/dhcprelay/dhcprelayTest.py:dhcprelay_exchange.test_dhcpRelay_1request
echo "Running IGMP join verify test"
docker exec $cnt nosetests -v /root/test/src/test/igmp/igmpTest.py:igmp_exchange.test_igmp_join_verify_traffic
echo "Running VROUTER test with 5 routes"
docker exec $cnt nosetests -v /root/test/src/test/vrouter/vrouterTest.py:vrouter_exchange.test_vrouter_with_5_routes
echo "Running CORD subscriber tests"
docker exec $cnt nosetests -v /root/test/src/test/cordSubscriber/cordSubscriberTest.py:subscriber_exchange.test_cord_subscriber_join_recv
