# CORD TESTER
The CORD Automated Tester Suite is an extensible end-to-end system test suite targeting CORD PODs. 
Here we set it up for single-node CORD .

# Setting up CORD tester for a single-node CORD environment
* Details can be found at:
* `https://github.com/open-cloud/openstack-cluster-setup`

# Get started
* `wget https://raw.githubusercontent.com/open-cloud/openstack-cluster-setup/master/scripts/single-node-pod.sh`
* `bash single-node-pod.sh [-t] [-e]`
  * With no options, the script installs the OpenStack services and a simulated fabric. It creates VMs for
    XOS and ONOS but does not start these services.
  * Adding the `-t` option will start XOS, bring up a vSG, install a test client, and run a simple E2E test.
  * Adding the `-e` option will add the [ExampleService](http://guide.xosproject.org/devguide/exampleservice/) 
    to XOS (and test it if `-t` is also specified).

* [How to install](#how_to_install)
* [How to use](#how_to_use)

##  <a name="how_to_install">How to install and run cord-tester for CORD

```bash
$ git clone https://github.com/opencord/cord-tester.git
$ cd cord-tester/src/test/setup/

$ sudo ./cord-test.py -h
usage: cord-test.py [-h] {run,list,build,cleanup} ...

Cord Tester

positional arguments:
  {run,list,build,cleanup}
    run                 Run cord tester
    list                List test cases
    build               Build cord test container images
    cleanup             Cleanup test containers

optional arguments:
  -h, --help            show this help message and exit

$ sudo ./cord-test.py run -h
usage: cord-test.py run [-h] [-t TEST_TYPE] [-o ONOS] [-r] [-q] [-a APP] [-p]
                        [-e TEST_CONTROLLER] [-k] [-s]
                        [-u {test,quagga,radius,all}]
optional arguments:
  -h, --help            show this help message and exit
  -t TEST_TYPE, --test-type TEST_TYPE
                        Specify test type or test case to run
  -o ONOS, --onos ONOS  ONOS container image
  -q, --quagga          Provision quagga container for vrouter
  -a APP, --app APP     Cord ONOS app filename
  -p, --olt             Use OLT config
  -e TEST_CONTROLLER, --test-controller TEST_CONTROLLER
                        External test controller ip for Onos and/or radius
                        server. Eg: 10.0.0.2/10.0.0.3 to specify ONOS and
                        Radius ip to connect
  -r SERVER, --server SERVER
                        ip:port address to connect for cord test server for
                        container requests
  -k, --keep            Keep test container after tests
  -s, --start-switch    Start OVS when running under OLT config
  -u {test,quagga,radius,all}, --update {test,quagga,radius,all}
                        Update cord tester container images. Eg:
                        --update=quagga to rebuild quagga image.
                        --update=radius to rebuild radius server image.
                        --update=test to rebuild cord test image.(Default)
                        --update=all to rebuild all cord tester images.
  -n NUM_CONTAINERS, --num-containers NUM_CONTAINERS
                        Specify number of test containers to spawn for tests

$  sudo ./cord-test.py list -h
usage: cord-test.py list [-h] [-t TEST]

optional arguments:
  -h, --help            show this help message and exit
  -t TEST, --test TEST  Specify test type to list test cases. Eg: -t tls to
                        list tls test cases. -t tls-dhcp-vrouter to list
                        tls,dhcp and vrouter test cases. -t all to list all
                        test cases.
 sudo ./cord-test.py build -h
usage: cord-test.py build [-h] {quagga,radius,test,all}

positional arguments:
  {quagga,radius,test,all}

optional arguments:
  -h, --help            show this help message and exit

## Setup prerequisites
$ sudo ./prerequisites.sh --cord

## Build container images
$ sudo ./cord-test.py build test

## Initiate a setup for test
$ sudo ./cord-test.py setup --olt -e 192.168.122.110/172.17.0.2

192.168.122.110 : ONOS running on compute node 192.168.122.110
172.17.0.2 : ONOS accessible radius server.

## Once above steps are done
$ sudo docker attach cord-tester1
$ cd /root/test/src/test/cordSubscriber
$ nosetests -v cordSubscriberTest.py

```
This would run a CORD Subscriber channel surfing tests and do a get to google.com.
Channel jump test does channel surfing by joining/leaving random channels and validation .
```
```
olt_config.json specifies the subscriber and test container configuration.
```
* For cleanup
```
$ sudo ./cord-test.py cleanup --olt
```
```
$ sudo pkill -f cord-test
```
