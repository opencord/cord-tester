# Testing CiaB (CORD-IN-A-BOX) Using CORD TESTER

The CORD Automated Tester Suite is an extensible end-to-end system test suite
now targeting CORD in a BOX also.

## Prerequisites

* Python 2.7 or later
* Docker

## How to install

```shell
git clone https://github.com/opencord/cord-tester.git
cd cord-tester
cd src/test/setup/
```

Run `prerequisites.sh --cord` (It gets you needed dependencies and tools to start)

* Build all required test container images

```shell
sudo ./cord-test.py build all
```

* If you want , you can also pull latest onos from docker hub for test setup.

```shell
sudo docker pull onosproject/onos:latest
```

* Else setup for test with onos instances (onos-cord and onos-fabric) running
  in CiaB.

* For Onos cord (Access side onos)

```shell
sudo ./cord-test.py setup -m manifest-cord.json
```

* For Fabric onos

```shell
sudo ./cord-test.py setup -m manifest-fabric.json
```

* For running tests using specific test container.

```shell
sudo ./cord-test.py run -t tls:eap_auth_exchange.test_eap_tls -c cord-tester1
```

## How to use

Help:

```shell
sudo ./cord-test.py -h
```

List test cases for individual modules or list all tests.

```shell
sudo ./cord-test.py list -t <module name>/ all
```

Cleanup:

```shell
sudo ./cord-test.py cleanup -m manifest-cord.json
```

## Individual tests

Running test case of indivdual modules, some examples:

### TLS

```shell
sudo ./cord-test.py  run -t tls:eap_auth_exchange.test_eap_tls
```

### IGMP

```shell
sudo ./cord-test.py  run -t igmp:igmp_exchange.test_igmp_join_verify_traffic
```

### VROUTER

```shell
sudo ./cord-test.py run -t vrouter:vrouter_exchange.test_vrouter_with_5_routes
```

### DHCP

```shell
sudo ./cord-test.py  run -t dhcp:dhcp_exchange.test_dhcp_1request
```


