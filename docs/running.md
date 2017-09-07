# CORD TESTER
The CORD Automated Tester Suite is an extensible end-to-end system test suite targeting CORD PODs. 

* [How to install](#how_to_install)
* [How to use](#how_to_use)

## Prerequisites

* Python 2.7 or later
* Docker
* vagrant(Optional)

##  <a name="how_to_install">How to install

```bash
$ git clone https://github.com/opencord/cord-tester.git
$ cd cord-tester
$ vagrant up
$ vagrant ssh cordtest
$ cd /cord-tester/src/test/setup/
$ Run prerequisites.sh(It gets you needed dependencies and tools to start)
* Build all required test container images
$ sudo ./cord-test.py build all
$ sudo ./cord-test.py -h
usage: cord-test.py [-h] {run,setup,xos,list,build,metrics,start,cleanup} ...

Cord Tester

positional arguments:
  {run,setup,xos,list,build,metrics,start,cleanup}
    run                 Run cord tester
    setup               Setup cord tester environment
    xos                 Building xos into cord tester environment
    list                List test cases
    build               Build cord test container images
    metrics             Info of container
    start               Start cord tester containers
    cleanup             Cleanup test containers

optional arguments:
  -h, --help            show this help message and exit

$ sudo ./cord-test.py run -h
usage: cord-test.py run [-h] [-t TEST_TYPE] [-o ONOS] [-q] [-a APP] [-l]
                        [-e TEST_CONTROLLER] [-r SERVER] [-k] [-s]
                        [-u {test,quagga,radius,all}] [-n NUM_CONTAINERS]
                        [-c CONTAINER] [-m MANIFEST] [-p PREFIX] [-d]
                        [-i IDENTITY_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -t TEST_TYPE, --test-type TEST_TYPE
                        Specify test type or test case to run
  -o ONOS, --onos ONOS  ONOS container image
  -q, --quagga          Provision quagga container for vrouter
  -a APP, --app APP     Cord ONOS app filename
  -l, --olt             Use OLT config
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
  -c CONTAINER, --container CONTAINER
                        Test container name for running tests
  -m MANIFEST, --manifest MANIFEST
                        Provide test configuration manifest
  -p PREFIX, --prefix PREFIX
                        Provide container image prefix
  -d, --no-switch       Dont start test switch.
  -i IDENTITY_FILE, --identity-file IDENTITY_FILE
                        ssh identity file to access compute nodes from test
                        container
$ sudo ./cord-test.py build -h
usage: cord-test.py build [-h] [-p PREFIX] {quagga,radius,test,all}

positional arguments:
  {quagga,radius,test,all}

optional arguments:
  -h, --help            show this help message and exit
  -p PREFIX, --prefix PREFIX
                        Provide container image prefix
$sudo ./cord-test.py list -h
usage: cord-test.py list [-h] [-t TEST]

optional arguments:
  -h, --help            show this help message and exit
  -t TEST, --test TEST  Specify test type to list test cases. Eg: -t tls to
                        list tls test cases. -t tls-dhcp-vrouter to list
                        tls,dhcp and vrouter test cases. -t all to list all
                        test cases.
```
* If you want to run cord-tester without Vagrant and already have a Ubuntu 14.04 server installed.
```
$ git clone https://github.com/opencord/cord-tester.git
$ cd cord-tester/src/test/setup/
$ sudo ./prerequisites.sh
```
* Then follow the same instructions as mentioned in above section.


## <a name="how_to_use">How to use
* eval.sh will run all the test cases for you.
```
$ sudo ./eval.sh
```
* Running all test cases in a module (for e.g DHCP)
```
$ sudo ./cord-test.py run -t dhcp
```
* Running single test case in a module 
```
$ sudo ./cord-test.py  run -t dhcp:dhcp_exchange.test_dhcp_1request
```
* Running all test cases 
```
$ sudo ./cord-test.py  run -t all
```
* Check list of test cases
```
$ sudo ./cord-test.py list -t all/<Module name>
```
* Check list of specific module 
```
$ sudo ./cord-test.py list -t dhcp
```
* Cleanup all test containers
```
$ sudo ./cord-test.py cleanup
```
* For other options, run with -h option.
## CORD API TESTS

This module contains tests using XOS APIs.
Testcases are written in RobotFramework utilizing some automated python library framework.  

## Prerequisites:
 
  * Robot Framework

## Install Robot Framework:
```bash
     $ sudo pip install robotframework
     $ sudo pip install pygments
     $ sudo apt-get install python-wxgtk2.8
     $ sudo pip install robotframework-ride
```
   - To bring up IDE for the robot framework
```bash
   $ ride.py
```
## Execute testcases:
   * Testcases can be run using ride.py IDE
   * Or From the command line
```bash
     $ cd cord-tester/src/test/cord-api/Tests
     $ pybot <testcase.txt>
```
## Input Files for the testcases
* Input files for the testcases are present in the "Tests/data" directory, a set of input files to run the testcases
