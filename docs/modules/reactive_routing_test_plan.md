**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

** Reactive Routing Test Cases (Implemented and Planned) : **

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
    <td>RR_1</td>
    <td>Verify the traffic flow when both the hosts are in SDN network</td>
    <td></td>
    <td>Configure 2 hosts to be in SDN network . Check the traffic flow</td>
    <td>There should be traffic flow between 2 hosts</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_2</td>
    <td>Verify the traffic flow from SDN host to internet host.</td>
    <td></td>
    <td>Configure one host in SDN network and another host in internet.
Check the traffic flow</td>
    <td>There should be traffic flow from SDN network to internet</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_3</td>
    <td>Verify the traffic flow from internet host to SDN host.</td>
    <td></td>
    <td>Configure one host in internet and another host in SDN network.
Check the traffic flow</td>
    <td>There should be a traffic flow from internet host to SDN network.</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_4</td>
    <td>Verify the traffic drop when there is no matchable ip prefix</td>
    <td></td>
    <td>Send a traffic from one host to another host which is not matching with the file sdnip.json
 </td>
    <td>Packets should get dropped.</td>
    <td></td>
  </tr>
</table>
