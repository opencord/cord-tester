**Cord-Tester**

**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Cbench **

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
    <td>cbench_1</td>
    <td>Verify benchamark testing on igmp on ONOS controller</td>
    <td>test_cbench_igmp</td>
    <td>Install cbench tool
Execute cbench commands for igmp traffic test</td>
    <td>Tool should get install
Igmp traffic has to be received properly
ONOS should not hang/crash</td>
    <td></td>
  </tr>
  <tr>
    <td>cbench_2</td>
    <td>Verify throughput benchmark testing on ONOS controller</td>
    <td>test_cbench_throughput_test</td>
    <td>Install cbench tool
Initiate throughput traffic testing </td>
    <td>ONOS should not crash/hang </td>
    <td></td>
  </tr>
  <tr>
    <td>Cbench_3</td>
    <td>Verify latency benchmark testing on ONOS controller </td>
    <td>test_cbench_latency_test</td>
    <td>Install cbench tool
Initiate traffic to test latency
</td>
    <td>ONOS should not crash/hang
 </td>
    <td></td>
  </tr>
</table>

