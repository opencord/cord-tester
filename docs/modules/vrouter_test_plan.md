**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Vrouter Test Cases (Implemented and Planned) : **

** Start the quagga container and activate the Vrouter app.**

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
    <td>Vrouter_1</td>
    <td>Test vrouter with 5 routes</td>
    <td>test_vrouter_with_5_routes</td>
    <td> 1.Generate vrouter configuration with new network configuration file
Start onos and Quagga
Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_2</td>
    <td>Test vrouter with 5 routes with 2 peers</td>
    <td>test_vrouter_with_5_routes_2_peers</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 2 peers and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_3</td>
    <td>Test vrouter with 5 routes with stopping Quagga</td>
    <td>test_vrouter_with_5_routes_stopping_quagga</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check
4. Stop Quagga and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_4</td>
    <td>Test vrouter with 50 routes with stopping Quagga</td>
    <td> test_vrouter_with_50_routes_stopping_quagga</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check
4. Stop Quagga and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_5</td>
    <td>Test vrouter with 6 routes with 3 peers</td>
    <td> test_vrouter_with_6_routes_3_peers</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 2 peers and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_6</td>
    <td>Test vrouter with 50 routes</td>
    <td> test_vrouter_with_50_routes</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_7</td>
    <td>Test vrouter with 50 routes and 5 peers</td>
    <td> test_vrouter_with_50_routes_5_peers</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 5 peers and check</td>
    <td>It should be successful..</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_8</td>
    <td>Test vrouter with 100 routes</td>
    <td> test_vrouter_with_100_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_9</td>
    <td>Test vrouter with 100 routes and 10 peers</td>
    <td> test_vrouter_with_100_routes_10_peers</td>
    <td>   1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 10 peers and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_10</td>
    <td>Test vrouter with 300 routes</td>
    <td> test_vrouter_with_300_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_11</td>
    <td>Test vrouter with 1000 routes</td>
    <td> test_vrouter_with_1000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_12</td>
    <td>Test vrouter with 10000 routes</td>
    <td> test_vrouter_with_10000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_13</td>
    <td>Test vrouter with 100000 routes</td>
    <td> test_vrouter_with_100000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_14</td>
    <td>Test vrouter with 1000000 routes</td>
    <td>test_vrouter_with_1000000_routes </td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_15</td>
    <td>Test vrouterwith route update</td>
    <td>test_vrouter_with_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_16</td>
    <td>Test vrouterwith classA route update</td>
    <td>test_vrouter_with_classA_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_17</td>
    <td>Test vrouterwith classB route update</td>
    <td>test_vrouter_with_classB_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_18</td>
    <td>Test vrouterwith class less route update</td>
    <td>test_vrouter_with_classless_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_19</td>
    <td>Test vrouter with classA duplicate route update</td>
    <td>test_vrouter_with_classA_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_20</td>
    <td>Test vrouter with classB duplicate route update</td>
    <td>test_vrouter_with_classB_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_21</td>
    <td>Test vrouter with classless duplicate route update</td>
    <td>test_vrouter_with_classless_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_22</td>
    <td>Test vrouter with invalid peers</td>
    <td>test_vrouter_with_invalid_peers</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Not Tested</td>
  </tr>
  <tr>
    <td>Vrouter_23</td>
    <td>Test vrouter with traffic sent between peers connected to onos</td>
    <td>test_vrouter_with_traffic_sent_between_peers_connected_to_onos</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Not Tested</td>
  </tr>
  <tr>
    <td>Vrouter_24</td>
    <td>Test vrouter with routes time expire</td>
    <td>test_vrouter_with_routes_time_expire</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_25</td>
    <td>Test vrouter with unreachable route</td>
    <td>test_vrouter_with_unreachable_route</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_26</td>
    <td>Test vrouter with enabling disabling vrouter app</td>
    <td>test_vrouter_with_enabling_disabling_vrouter_app</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_27</td>
    <td>Test vrouter with adding new routes in routing table</td>
    <td>test_vrouter_with_adding_new_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_28</td>
    <td>Test vrouter with removing old routes in routing table</td>
    <td>test_vrouter_with_removing_old_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_29</td>
    <td>Test vrouter modifying nexthop route in routing table</td>
    <td>test_vrouter_modifying_nexthop_route_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_30</td>
    <td>Test vrouter deleting alternative nexthop in routing table</td>
    <td>test_vrouter_deleting_alternative_nexthop_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_31</td>
    <td>Test vrouter deleting some routes in routing table</td>
    <td>test_vrouter_deleting_some_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_32</td>
    <td>Test vrouter deleting and adding routes in routing table</td>
    <td>test_vrouter_deleting_and_adding_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
</table>
