# Setting Up CORD Tester Environment

## Configure Automation Framework

* When the POD/Cord-in-a-Box is installed, cord-tester repo is downloaded on
  the head node at `/opt/cord/test` directory

* Tests can be run directly from the headnode or from a different VM then it
  can be done using the following command:

  ```bash
  git clone https://gerrit.opencord.org/cord-tester
  ```

* Before executing any tests, proper modules need to be installed which can be
  done using the following command:

  ```bash
  cd /opt/cord/test/cord-tester/src/test/setup
  sudo ./prerequisites.sh --cord
  ```

## Executing Tests

Most of the tests in cord-tester framework are written in `python` and
`RobotFramework`.  Few examples for test execution are shown below

* Executing a sample test

  ```bash
  cd /opt/cord/test/cord-tester/src/test/robot/
  pybot SanityPhyPOD.robot
  ```

### Executing Control Plane Tests

* Each control plane test uses input data in `json` format which are present
  under `/opt/cord/test/cord-tester/src/test/cord-api/Tests/data`

* Before running control plane tests, a properties file need to be edited as
  shown below.  Update the following attributes accordingly

  ```bash
  $ cd /opt/cord/test/cord-tester/src/test/cord-api/Properties
  $ cat RestApiProperties.py

  SERVER_IP = 'localhost'
  SERVER_PORT = '9101'
  USER = 'xosadmin@opencord.org'
  PASSWD = ''
  ```

* To run tests

  ```bash
  cd /opt/cord/test/cord-tester/src/test/cord-api/
  pybot <testcase.txt>
  ```

## Executing Functional/Module Tests

* There are several functional tests written to test various modules of CORD
  independently.

* Before executing module based tests, following steps need to be performed
  which will create a `test container` and sets up the environment in the
  container to run tests.

  ```bash
  cd /opt/cord/test/cord-tester/src/test/setup/
  sudo ./cord-test.py setup -m manifest-cord.json
  ```

* Run a single test from a module

  ```bash
  sudo ./cord-test.py  run -t dhcp:dhcp_exchange.test_dhcp_1request
  ```

  For more detailed explanations of the cord-tester options please see [Running
  Tests](running.md).

