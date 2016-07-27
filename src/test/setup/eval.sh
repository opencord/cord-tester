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
olt_config="$(dirname $0)/olt_config.json"
sub=0
if grep -q br-int $olt_config; then
  sub=1
fi
if [ $sub -eq 1 ]; then
    sed -i 's,br-int,ovsbr0,g' $olt_config
fi
function finish {
    $cord_tester cleanup --olt
    pkill -f cord-test
    if [ $sub -eq 1 ]; then
        sed -i 's,ovsbr0,br-int,g' $olt_config
    fi
}
trap finish EXIT
$cord_tester setup --olt --start-switch
cnt=`docker ps -lq`
echo "Running TLS authentication test"
docker exec $cnt nosetests -v /root/test/src/test/tls/tlsTest.py
echo "Running DHCP relay request test"
docker exec $cnt nosetests -v /root/test/src/test/dhcprelay/dhcprelayTest.py:dhcprelay_exchange.test_dhcpRelay_1request
echo "Running IGMP join verify test"
docker exec $cnt nosetests -v /root/test/src/test/igmp/igmpTest.py:igmp_exchange.test_igmp_join_verify_traffic
echo "Running VROUTER test with 5 routes"
docker exec $cnt nosetests -v /root/test/src/test/vrouter/vrouterTest.py:vrouter_exchange.test_vrouter_with_5_routes
echo "Running CORD subscriber tests"
docker exec $cnt nosetests -v /root/test/src/test/cordSubscriber/cordSubscriberTest.py
