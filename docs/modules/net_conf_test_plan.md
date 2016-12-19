**Cord-Tester**

**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Netconf Test Cases (Implemented and Planned) : **


<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Netconf_1</td>
    <td>Check for devices in ONOS</td>
    <td></td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
2.  onos> devices</td>
    <td>Devices should be present in ONOS.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netconf_2</td>
    <td>Verify the logs in ONOS</td>
    <td></td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
 2. onos> devices.
3. Onos>logs</td>
    <td>logs shouldn't contain NETCONF related exceptions</td>
    <td></td>
  </tr>
</table>
