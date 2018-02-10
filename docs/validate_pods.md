# Validating PODs

PODs are deployed everynight using Jenkins Build System.
After a successful installation of the POD, test jobs are triggered which validate the
following categories of tests

* Post Installation Verification

* Sanity Tests

* Functional Tests (Control and Data Plane)

* Soak Tests

## Post Installation Tests

These tests perform the following validations

* Required Docker Containers are up and running
* Synchronizer Logs are correct
* Required ONOS applications are installed in ONOS Fabric and ONOS CORD
* ONOS Logs does not contain any errors

To execute the test, perform the following from the head node

```bash
cd /opt/cord/build
make collect-diag
cd /opt/cord/test/cord-tester/src/test/diag
pybot verifyCollectDiag.robot
```

## Sanity Checks on the installed POD

Following validations are performed after installation:

* Headnode interfaces are up and has external connectivity
* Compute nodes can ping each other through the fabric
* Computes nodes can ping the switches
* `cordvtn` app is running and identifies the nodes and the fabric devices
* Required MAAS services are up and running
* Status of Docker containers
* Juju Service States
* MAAS Cli commands
* Openstack LXD Container States
* Fabric Switch services
* Ping all Fabric switches

To execute the test, perform the following on the headnode

```bash
cd /opt/cord/test/cord-tester/src/test/robot
pybot SanityPhyPOD.robot
```
## Functional Tests

Control and Data plane tests can be executed on the POD once the
sanity checks are successful.

### Executing Control Plane Tests

To validate the functionality of vSG instance creations and there by
validating the end-end functionality checks on the related APIs, the
following control plane test can be executed.

* Edit the attributes shown below in the properties file

```bash
$ cd  /opt/cord/test/cord-tester/src/test/cord-api/Properties
$ cat RestApiProperties.py

SERVER_IP = 'localhost'
SERVER_PORT = '9101'
USER = 'xosadmin@opencord.org'
PASSWD = ''
```
* To run the test

```bash
cd /opt/cord/test/cord-tester/src/test/cord-api/
pybot Ch_MultiInstance.txt
```

### Data Plane Tests

Once the vSG instances are created after execution of the above
`control plane` test, `data plane` tests can be executed to verify
if the data traffic passes through the created vSG/vcpe from the
cord-test container which simulates the interface that was created
with similar `s_tag and c_tag`

Following steps are performed when the data plane test is executed.

* vSG Instances in OpenStack Nova are created per subscriber created
* vSG Instances are ACTIVE and are reachable via mgmt interface
* Configures X-Connects for subscribers in onos-fabric for the overlay fabric
* Configures a dhclient on the Cord-Tester containers interface that is being
  used as the vSG Subscriber
* Validates a DHCP IP address is received from the vCPE Container and external
connectivity is reachable through the vCPE

To run a data plane test, perform the following steps

* Update the `olt_config.json` file in the `setup` directory to include
  the `s_tag` and `c_tag` used in the Control-Plane Test with the
  reserved flag turned on and create the `cord test container`

```bash
$ cd /opt/cord/test/cord-tester/src/test/setup
$ cat out_config.json
{ "olt" : false,
  "uplink" : 2,
  "vlan" : 0,
  "port_map" : { "num_ports" : 11, "start_vlan" : 1000, "nr_switches": 1 },
  "vcpe" :
  [
        {
          "port" : "fabric", "type" : "reserved", "s_tag" : 415, "c_tag" : 222
        },
        {
          "port" : "fabric", "type" : "reserved", "s_tag" : 333, "c_tag" : 888
        },
        {
          "port" : "fabric", "type" : "reserved", "s_tag" : 555, "c_tag" : 999
        },
        {
          "port" : "fabric", "type" : "reserved", "s_tag" : 666, "c_tag" : 661
        }
      ]
}
```

```bash
sudo ./cord-test.py setup -m manifest-onf-cord.json
```

* Validate the data plane connectivity

```bash
cd /opt/cord/test/cord-tester/src/test/vsg
pybot vsg_dataplane_test.robot
```

>NOTE: All the control and data plane tests can also be executed on a `Virtual POD(Cord-in-a-Box)`
>using the above procedure. Except for the data plane tests, where it needs to be run
>using a different option as there are no crossconnects required to be provisioned on CiaB.

```bash
pybot -e xconnect vsg_dataplane_test.robot
```
