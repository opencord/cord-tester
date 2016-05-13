# CORD TESTER
The CORD Automated Tester Suite is an extensible end-to-end system test suite targeting CORD PODs. 

* [How to install](#how_to_install)
* [How to use](#how_to_use)

## Prerequisites

* Python 2.7 or later
* Docker
* vagrant

##  <a name="how_to_install">How to install

```bash
$ git clone https://github.cyanoptics.com/cord-lab/cord-tester.git
$ cd cord-tester
$ vagrant up
$ vagrant ssh cordtest
$ cd src/test/setup/
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
  -r, --radius          Start Radius service
  -q, --quagga          Provision quagga container for vrouter
  -a APP, --app APP     Cord ONOS app filename
  -p, --olt             Use OLT config
  -e TEST_CONTROLLER, --test-controller TEST_CONTROLLER
                        External test controller ip for Onos and/or radius
                        server. Eg: 10.0.0.2/10.0.0.3 to specify ONOS and
                        Radius ip to connect
  -k, --keep            Keep test container after tests
  -s, --start-switch    Start OVS when running under OLT config
  -u {test,quagga,radius,all}, --update {test,quagga,radius,all}
                        Update cord tester container images. Eg:
                        --update=quagga to rebuild quagga image.
                        --update=radius to rebuild radius server image.
                        --update=test to rebuild cord test image.(Default)
                        --update=all to rebuild all cord tester images.
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
```
* If you want to run cord-tester without Vagrant and already have a Ubuntu 14.04 server installed.
```
$ git clone https://github.cyanoptics.com/cord-lab/cord-tester.git
$ cd cord-tester/src/test/setup/
$ prerequisites.sh
```
* Then follow the same instructions as mentioned in above section.


## <a name="how_to_use">How to use
* eval.sh will run all the test cases for you.
```
$ ./eval.sh
```
* Running all test cases in a module (for e.g DHCP)
```
$ sudo ./cord-test.py run -t dhcp
```
* Running single test case in a module 
```
$ sudo ./cord-test.py  -t dhcp:dhcp_exchange.test_dhcp_1request
```
* If you want to check a list of test cases
```
$ sudo ./cord-test.py list
```
* IF you want to clean up all 
```
$ sudo ./cord-test.py clean
```

* For other options, run with -h option.

