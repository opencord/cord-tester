# Validating PODs

PODs(physical nodes) are deployed everynight using Jenkins Build System.  After a successful
installation of the POD, test jobs are triggered which validate the following
categories of tests

* Post Installation Verification

* Functional Tests

## Post Installation Tests

These tests perform the following validations

* Required services are running
* All deployments are successfully rolled out and matches replicas to available replicas
* All pods are running
* Pods have external connectivity
* Pods can ping the kube-system namespace
* Nodes are healthy (checking “ready”, “outofdisk”, “memorypressure”, “diskpressure”)
* Required containers are in running state

To execute the test, perform the following from the client machine

```bash
cd cord-tester/src/test/diag
pybot SanityK8Pod.robot
```

## Functional Tests

Control tests can be executed on the POD once the
sanity checks are successful.

### Executing Control Plane Tests

To validate the end-end functionality checks on the RCORD Lite APIs, the
following control plane test can be executed.

* Edit the attributes shown below in the properties file

```bash
$ cd  cord-tester/src/test/cord-api/Properties
$ cat RestApiProperties.py

SERVER_IP = 'localhost'
SERVER_PORT = '9101'
USER = 'xosadmin@opencord.org'
PASSWD = ''
```

* To run the tests

```bash
cd cord-tester/src/test/cord-api/Tests/
pybot VOLTDevice_Test.txt
pybot RCORDLite_E2ETest.txt 
```

### Data Plane Tests

For CORD 6.0 release, data plane tests are executed manually on the
POD using OLT/ONU.
