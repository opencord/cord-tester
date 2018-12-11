# Setting Up CORD Tester Environment

## Configure Automation Framework

* Tests can be run directly from your local machine or from a different VM by exporting the
  configuration file for the target CORD servers.
  
* Download the `cord-tester` repo using the following command:

  ```bash
  git clone https://gerrit.opencord.org/cord-tester
  ```

* Before executing any tests, proper modules need to be installed which can be
  done using the following command:

  ```bash
  cd cord-tester/src/test/setup
  sudo ./prerequisites.sh --cord
  ```

## Executing Tests

Most of the tests in cord-tester framework are written in `python` and
`RobotFramework`.  Few examples for test execution are shown below

* Export the configuration file(file that was generated during kubernetes/helm installation)

  ```bash
  export KUBECONFIG=/home/cord/cord-pod1.conf
  ```
  Assuming that `cord-pod1.conf` file is present in `/home/cord` directory

* Executing a sample test

  ```bash
  cd cord-tester/src/test/robot/
  robot SanityK8POD.robot
  ```

### Executing Control Plane Tests

* Each control plane test uses input data in `json` format which are present
  under `cord-tester/src/test/cord-api/Tests/data`

* Before running control plane tests, a properties file need to be edited as
  shown below.  Update the following attributes accordingly

  ```bash
  $ cd cord-tester/src/test/cord-api/Properties
  $ cat RestApiProperties.py

  SERVER_IP = 'localhost'
  SERVER_PORT = '30006'
  USER = 'admin@opencord.org'
  PASSWD = ''
  ```

* To run tests

  ```bash
  cd cord-tester/src/test/cord-api/Tests/
  robot <testcase.txt>
  ```
