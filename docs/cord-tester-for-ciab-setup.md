# Testing CiaB(CORD-IN-A-BOX) Using CORD TESTER
The CORD Automated Tester Suite is an extensible end-to-end system test suite now targeting CORD in a BOX also.

* [How to install](#how_to_install)
* [How to use](#how_to_use)

## Prerequisites

* Python 2.7 or later
* Docker

##  <a name="how_to_install">How to install

```bash
$ git clone https://github.com/opencord/cord-tester.git
$ cd cord-tester
$ cd src/test/setup/
$ Run prerequisites.sh --cord
  (It gets you needed dependencies and tools to start)
* Build all required test container images
$ sudo ./cord-test.py build all
* If you want , you can also pull latest onos from docker hub for test setup.
$ sudo docker pull onosproject/onos:latest
* Else setup for test with onos instances (onos-cord and onos-fabric) running in CiaB.
* For Onos cord (Access side onos)
$ sudo ./cord-test.py setup -m manifest-cord.json
* For Fabric onos
$ sudo ./cord-test.py setup -m manifest-fabric.json
* For running tests using specific test container.
$ sudo ./cord-test.py run -t tls:eap_auth_exchange.test_eap_tls -c cord-tester1
```
##   <a name="how_to_use">How to use
```
* Running test case of indivdual modules, some examples
```
```
* TLS
```
```
$ sudo ./cord-test.py  run -t tls:eap_auth_exchange.test_eap_tls
```
```
* IGMP
```
```
$ sudo ./cord-test.py  run -t igmp:igmp_exchange.test_igmp_join_verify_traffic
```
```
* VROUTER
```
```
$ sudo ./cord-test.py run -t vrouter:vrouter_exchange.test_vrouter_with_5_routes
```
```
* DHCP
```
```
$ sudo ./cord-test.py  run -t dhcp:dhcp_exchange.test_dhcp_1request
```
```
* For help and usage use -h option in all levels of menu
```
```
$ sudo ./cord-test.py -h
```
```
* For listing test cases of indivisual module or list all tests.
```
```
$ sudo ./cord-test.py list -t <module name>/ all
```
```
* Cleanup
```
```
$ sudo ./cord-test.py cleanup -m manifest-cord.json
```


