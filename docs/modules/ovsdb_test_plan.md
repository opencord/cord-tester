**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Ovsdb Test Cases (Implemented and Planned) : **


**Onos should be running well and Install feature ovsdb-web-provider ovsdb onos-core-netvirt on onos.**


<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>TestSteps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>OVSDB_1</td>
    <td>OVSDB connection setup and teardown</td>
    <td></td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS.
2.Configure ovs-vsctl del-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS. </td>
    <td>1.OVSDB connection is up.
2.OVSDB connection is down.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_2</td>
    <td>Default configuration of bridge and vxlan install</td>
    <td></td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1.
2.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1 and OVS2.</td>
    <td>1.OVS1 has an br_int.
2.OVS1 and OVS2 has br_int and vxlan tunnel.
3.ONOS devices add two sw.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_3</td>
    <td>OPENFLOW connection setup automatic</td>
    <td></td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the Openflow connection on ONOS. </td>
    <td>OPENFLOW connection is up.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_4</td>
    <td>Default flow tables install</td>
    <td></td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the default flow tables on OVS and ONOS.</td>
    <td>1.default flows is correct.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_5</td>
    <td>Simulation VM go online check flow tables install</td>
    <td></td>
    <td>1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the flow tables on OVS and ONOS.
2.Create a port on OVS1.Check the flow tables on OVS and ONOS.
3.Create a port on OVS2.Check the flow tables on OVS and ONOS.
 </td>
    <td>1.OVS and ONOS have default flows.
2.OVS and ONOS add correct flows.
3.OVS and ONOS add correct flows. </td>
    <td></td>
  </tr>
</table>
