# Validating PODs

PODs(physical nodes) are deployed everynight using Jenkins Build System.  After a successful
installation of the POD, test jobs are triggered which validate the following
categories of tests


* Functional Tests


## Functional Tests

Control tests can be executed on the POD once it has been successfully deployed.

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
robot VOLTDevice_Test.txt
```

### Data Plane Tests

Data plane tests include the workflow validations. Follow the guide above to edit the properties file before running the tests.

**Validating AT&T workflow**

Test scripts and input data for validating AT&T workflow are under `cord-tester/src/test/cord-api/Tests/WorkflowValidations`. The same test script e.g. `ATT_Test001.robot` works with different POD setups. Instead of hardcoding the POD specific variables in the test script, it relies on a separated configuration file which describes POD setup. To create a configuration file for your POD please take a look at [this example](https://github.com/opencord/pod-configs/blob/master/deployment-configs/flex-ocp-cord.yaml).

Input data are stored under `cord-tester/src/test/cord-api/Tests/WorkflowValidations/data/`. Please create a new folder with the name of your POD and copy and data files from e.g. `flex-ocp-cord` folder and edit them with the correct values on your POD.

Also make sure that the variables in the test script (e.g. `ATT_Test001.robot`) are correct. Specifically, verify that `${POD_NAME}` is the same as the folder name you created above, and `${KUBERNETES_CONF}` is pointing to your Kubernetes configuration file.

After updating all these POD specific values, execute the following commands to trigger the test

```bash
cd cord-tester/src/test/cord-api/Tests/WorkflowValidations
robot -V PATH_TO_YOUR_POD_CONFIGURATION_FILE ATT_Test001.robot
 ```
Each scenario in ATT_Test001.robot is associated with `Tags` field, using which we can run a single scenario from the testcase as well.
To execute a single scenario for the test

```bash
cd cord-tester/src/test/cord-api/Tests/WorkflowValidations
robot -i test1 -V PATH_TO_YOUR_POD_CONFIGURATION_FILE ATT_Test001.robot
 ```

Note that `PATH_TO_YOUR_POD_CONFIGURATION_FILE` should point to the yaml file that describes your POD setup (see above).


**Seba-in-a-Box Tests**

Test scripts and input data for validating Seba-in-a-Box tests based on the ATT-Workflow profile are under `cord-tester/src/test/cord-api/Tests/WorkflowValidations/`. Test file:`SIAB.robot` Data files reside in the:`data/` directory. 

These tests have the same test scenarios as the Physical Pod tests, however they are scripted differently as the system of a virtual seba deployment (Seba-in-a-Box) is vastly different from the physical pod. To execute these tests after successfully installing "Seba-in-a-Box", execute the following commands:

```bash
cd cord-tester/src/test/cord-api/
source setup_venv.sh
cd Tests/WorkflowValidations/ && robot -x notready SIAB.robot
```
