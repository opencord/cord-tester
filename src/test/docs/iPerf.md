**Cord-Tester**

**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**iPerf **

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
    <td>iperf_1</td>
    <td>Verify benchmark testing of ONOS controller for tcp using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp</td>
    <td>Open a tcp session to ONOS controller </td>
    <td>ONOS should not crash/hang</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_2</td>
    <td>Verify benchmark testing of ONOS controller for udp using iperf tool</td>
    <td>test_iperf_network_performance_test_udp</td>
    <td>Open a udp connection to ONSO controller</td>
    <td>ONOS should not crash/hang </td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_3</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_40k</td>
    <td>Open tcp session to ONOS controller by setting window size to 40k
</td>
    <td>ONOS should not crash/hang
 </td>
    <td></td>
  </tr>
  <tr>
    <td>Iperf_4</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_120k</td>
    <td>Open tcp session to ONOS controller by setting window size to 120k</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_5</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_520k</td>
    <td>Open tcp session to ONOS controller by setting window size to 520k</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_6</td>
    <td>Verify benchmark testing  of ONOS controller for multiple tcp sessions </td>
    <td>test_iperf_network_performance_test_multiple_tcp_sessions</td>
    <td>Open multiple tcp sessions to ONOS controller </td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_7</td>
    <td>Verify benchmark testing of ONOS controller for multiple udp sessions</td>
    <td>test_iperf_network_performance_test_multiple_udp_sessions</td>
    <td>Open multiple udp sessions to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_8</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 90bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_90Bytes</td>
    <td>Open a tcp session with mss 90bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_9</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 1490bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_1490Bytes</td>
    <td>Open a tcp session with mss 1490bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_10</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 9000bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_9000Bytes</td>
    <td>Open a tcp session with mss 9000bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
</table>


