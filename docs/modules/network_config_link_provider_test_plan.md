**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Network Config Link Provider Test Cases (Implemented and Planned) : **

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
    <td>Netcfg_LP_1</td>
    <td>Check for the ACTIVE state of provider</td>
    <td></td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow</td>
    <td>There should be traffic flow over the links which are configured in netcfg.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_LP_2</td>
    <td>Verify the STRICT state</td>
    <td></td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow over the links which are not configured</td>
    <td>There should not be any traffic flow over the links which are configured in netcfg.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_LP_3</td>
    <td>Check for the error indication when source and destinat ion will not match</td>
    <td></td>
    <td>Configure a link in netcfg and check for the error indication when source and destination doesnt match </td>
    <td>A  link is created with an error indication, which allows the GUI to display an error indication to the user</td>
    <td></td>
  </tr>
</table>
