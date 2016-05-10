#!/usr/bin/env bash
cord_tester="$(dirname $0)/cord-test.py"
if [ ! -f $cord_tester ]; then
  cord_tester="$HOME/cord-tester/src/test/setup/cord-test.py"
fi
ONOS_IGMP="onosproject/onos:1.5"
docker kill cord-onos || true
docker kill cord-quagga || true
echo "Running TLS authentication test"
$cord_tester -r -t tls
echo "Running DHCP request test"
$cord_tester -q -t dhcp:dhcp_exchange.test_dhcp_1request
docker kill cord-onos || true
echo "Running IGMP join verify test"
$cord_tester -q -o $ONOS_IGMP -t igmp:igmp_exchange.test_igmp_join_verify_traffic
docker kill cord-onos || true
echo "Running VROUTER test with 5 routes"
$cord_tester -q -t vrouter:vrouter_exchange.test_vrouter_1