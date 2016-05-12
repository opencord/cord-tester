#!/usr/bin/env bash
cord_tester="$(dirname $0)/cord-test.py"
if [ ! -f $cord_tester ]; then
  cord_tester="$HOME/cord-tester/src/test/setup/cord-test.py"
fi
echo "Building all cord-tester images."
$cord_tester build all
docker kill cord-onos || true
docker kill cord-quagga || true
docker kill cord-radius || true
echo "Running TLS authentication test"
$cord_tester run -r -t tls
echo "Running DHCP request test"
$cord_tester run -t dhcp
echo "Running IGMP join verify test"
$cord_tester run -t igmp:igmp_exchange.test_igmp_join_verify_traffic
echo "Running VROUTER test with 5 routes"
$cord_tester run -q -t vrouter:vrouter_exchange.test_vrouter_1
