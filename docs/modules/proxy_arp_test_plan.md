**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Proxy Arp Test Cases (Implemented and Planned) : **


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
    <td>PARP_1</td>
    <td>Verify if Proxy ARP is working properly with 1 host creation</td>
    <td>test_proxyarp_with_1_host </td>
    <td>Configure host and Interface configurations in ONOS
Send an ARP request to host IP</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_2</td>
    <td>Verify if Proxy ARP is working properly with 10 host creation</td>
    <td> test_proxyarp_with_10_hosts</td>
    <td>1. Configure host and Interface configurations in ONOS
2. Send an ARP request to all 10  host IPs</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_3</td>
    <td>Verify if Proxy ARP is working properly with 50 host creation</td>
    <td> test_proxyarp_with_50_hosts</td>
    <td>1. Configure host and Interface configurations in ONOS
2. Send an ARP request to all 50 host IPs.</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td>PASS </td>
  </tr>
  <tr>
    <td>PARP_4</td>
    <td>Verify if Proxy ARP is working properly when it disable and re-enabled</td>
    <td> test_proxyarp_app_with_disabling_and_re_enabling

</td>
    <td>1. Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Disable proxy-arp app in ONSO and send arp requests again </td>
    <td>Proxy Arp should not response once it disabled </td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_5</td>
    <td>Verify if Proxy ARP is working properly for non-existing Host </td>
    <td>test_proxyarp_nonexisting_host</td>
    <td>1. Dont Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Now configure Host and Interface configurations in ONOS
4. Repeat step 2  </td>
    <td>Proxy Arp should not respond for arp requests sent to non-existing host IPs</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_6</td>
    <td>Verify if Proxy ARP is working properly for already existing host removed </td>
    <td>test_proxyarp_removing_host
</td>
    <td>1. Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Now Remove Host configuration in ONOS
4. Repeat step 2  </td>
    <td>Proxy Arp should not respond to arp  requests once the host configuration removed </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_7</td>
    <td>Verify if Proxy ARP is working properly for multiple arp requests at once</td>
    <td>test_proxyarp_concurrent_requests_with_multiple_host_and_different_interfaces
</td>
    <td>1. Configure 10 host and Interface configurations in ONOS
2. Send an ARP request to all 10 host IPs from 10 ports at once</td>
    <td>Proxy should response to all 10 arp requests received at once</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_8</td>
    <td>Verify if Proxy ARP is working properly when it disable and re-enabled in case of multiple requests at once</td>
    <td>test_proxyarp_disabling_enabling_app_initiating_concurrent_requests</td>
    <td>1. Configure 10 host and Interface configurations in ONOS
2.Send an ARP request to all 10 host IPs
3. Disable proxy-arp app in ONSO send arp requests again </td>
    <td>Proxy ARP should not respond once its disabled </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_9</td>
    <td>Verify if Proxy ARP is working properly in case of both existing and non-existing hosts </td>
    <td>test_proxyarp_with_existing_and_non_existing_hostIPs_initiating_concurrent_requests</td>
    <td>1. Configure 5 host and Interface configurations in ONOS
2.Send an ARP request for 10 host IPs
 </td>
    <td>Proxy ARP should respond to only existing Host IPs</td>
    <td>PASS</td>
  </tr>
</table>
