# Documentation

Use the cord-setup.sh bash script to run the tests for your test environment.

* In order to build a fresh test container before running the test, use the -b option like below:

'''
sudo ./cord-setup.sh -o onos:latest -a freeradius:latest -b onos:runtest -t dhcp-igmp
'''

* The above would build a docker container called onos:runtest before running the test.
Otherwise it tries to spawn an existing test container called, onos:nosetest to run the tests.

* To start the cord-tester, make sure you have onos and radius containers started and running.
* Then you can start it with the container id or tag like below:

'''
sudo ./cord-setup.sh -o onos:latest -a freeradius:latest -t dhcp
'''

* The above would spawn a test container and run the dhcp test.

* If you want to run a list of tests, just separate them with hypens.

'''
sudo ./cord-setup.sh -o onos:latest -a freeradius:latest -t dhcp-igmp-tls
'''

* If you want to run a specific test, you can give the classname.testname like below

'''
sudo ./cord-setup.sh -o onos:latest -a freeradius:latest -t dhcp:dhcp_exchange.test_dhcp_1request-igmp:test_igmp_1group_join_latency
'''

* If you want to spawn a test and kill the test container after the tests are done, specify the -k option like below.

'''
sudo ./cord-setup.sh -o onos:latest -a freeradius:latest -t dhcp -k
'''

* If you want to cleanup all the test containers by tag onos:nosetest, then use the -C cleanup option to cleanup test containers.

'''
sudo ./cord-setup.sh -o onos:latest -C onos:nosetest
'''

* For other options, run with -h option.
