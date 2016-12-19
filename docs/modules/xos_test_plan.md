**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**XOS**

<table>
  <tr>
    <td>	ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>XOS_1</td>
    <td>Verify XOS base container status</td>
    <td>test_xos_base_container_status</td>
    <td>Bring up XOS base container</td>
    <td>Container should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_2</td>
    <td>Verify Ping to XOS base container </td>
    <td> test_xos_base_container_ping</td>
    <td>Bring up XOS base container
Ping to the container </td>
    <td>Container should be Up and running
Ping to XOS base container should success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_3</td>
    <td>Verify XOS base container listening ports </td>
    <td>test_xos_base_container_listening_ports</td>
    <td>Bring up XOS base container
Grep all the listening ports on the container </td>
    <td>Ports status should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_4</td>
    <td>Verify XOS openstack sync container status</td>
    <td>test_xos_sync_openstack_container_status</td>
    <td>Bring up XOS openstack  sync container </td>
    <td>Container should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>
XOS_5</td>
    <td>
Verify Ping to XOS openstack sync container</td>
    <td> test_xos_sync_openstack_container_ping</td>
    <td>Bring up XOS openstack sync container
Ping to the container</td>
    <td>Container should be Up and running
Ping to XOS openstack sync  container should success
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_6</td>
    <td>Verify XOS openstack sync container listening ports</td>
    <td>test_xos_sync_openstack_container_listening_ports</td>
    <td>Bring up XOS openstack sync  container
Grep all the listening ports on the container</td>
    <td>Ports status should be Up
   </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_7</td>
    <td>Verify XOS postgresql container status</td>
    <td>test_xos_postgresql_container_status</td>
    <td>Bring up XOS postgresql container
</td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_8




</td>
    <td>Verify Ping to XOS portgresql container </td>
    <td>test_xos_postgresql_container_ping</td>
    <td>Bring up XOS postgresql container
Ping to the container</td>
    <td>Ping to postgresql container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_9</td>
    <td>Verify XOS postgresql container listening ports</td>
    <td>test_xos_postgresql_container_listening_ports</td>
    <td>Bring up XOS postgresql container
Grep all the listening ports on the container</td>
    <td>Ports should be Up </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_10</td>
    <td>Verify XOS syndicate ms container status</td>
    <td>test_xos_syndicate_ms_container_status</td>
    <td>Bring up  XOS syndicate ms container </td>
    <td>Container should be up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_11</td>
    <td>Verify Ping to XOS syndicate ms  container</td>
    <td>test_xos_syndicate_ms_container_ping</td>
    <td>Bring up  XOS syndicate ms container
Ping to the container</td>
    <td>Ping to the container should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_12</td>
    <td>Verify XOS postgresql container listening ports</td>
    <td>test_xos_syndicate_ms_container_listening_ports</td>
    <td>Bring up  XOS syndicate ms container
Grep all the open ports on the container </td>
    <td>All the ports should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_13

</td>
    <td>Verify XOS sync vtr container status  </td>
    <td>test_xos_sync_vtr_container_status</td>
    <td>Bring up XOS sync vtr container </td>
    <td>Container should be up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_14</td>
    <td>Verify ping to XOS sync vtr container </td>
    <td>test_xos_sync_vtr_container_ping</td>
    <td>Bring up XOS sync vtr container
Ping to the container </td>
    <td>Ping to the container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>cluster_15</td>
    <td>Verify listening ports on XOS sync vtr container  </td>
    <td>test_xos_sync_vtr_container_listening_ports</td>
    <td>Bring up XOS sync vtr container
Grep all the listening ports on the container </td>
    <td>Ports should be Up </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_16</td>
    <td>Verify XOS sync vsg container status</td>
    <td>test_xos_sync_vsg_container_status</td>
    <td>Bring up XOS sync vsg container
 </td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOX_17</td>
    <td>Verify ping to XOS sync vsg container</td>
    <td>test_xos_sync_vsg_container_ping</td>
    <td>Bring up XOS sync vsg container
Ping to the container
 </td>
    <td>Ping to the container should success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_18</td>
    <td>Verify listening ports on XOS sync vsg container</td>
    <td>test_xos_sync_vsg_container_listening_ports</td>
    <td>Bring up XOS sync vsg container
Grep all the listening ports on the container
 </td>
    <td>Ports should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_19</td>
    <td>Verify XOS sync onos container status</td>
    <td>test_xos_sync_onos_container_status</td>
    <td>Bring up XOS sync onos  container

</td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_20
</td>
    <td>Verify ping to XOS sync onos container</td>
    <td>test_xos_sync_onos_container_ping
</td>
    <td>Bring up XOS sync vsg container
Ping to the container
</td>
    <td>Ping to the container should success
</td>
    <td>

</td>
  </tr>
  <tr>
    <td>XOS_21</td>
    <td>Verify listening ports on XOS sync onos container</td>
    <td>test_xos_sync_onos_container_listening_ports</td>
    <td>Bring up XOS sync vsg container
Grep all the listening ports on the container
</td>
    <td>Ports should be Up</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_22



</td>
    <td>Verify XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_status</td>
    <td>Bring up XOS sync fabric container
</td>
    <td>Container should be Up and running
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_23</td>
    <td>Verify ping to XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_ping</td>
    <td>Bring up XOS sync fabric container
Ping to the container
</td>
    <td>Ping to the container should be success
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_24</td>
    <td>Verify listening ports on XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_listening_ports</td>
    <td>Bring up XOS sync fabric container
Grep all the open ports on the container</td>
    <td>Ports status should be Up</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_25</td>
    <td>Verify XOS sync vtn container status</td>
    <td>test_xos_sync_vtn_container_status </td>
    <td>Bring up XOS sync vtn container </td>
    <td>Container should be up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_26







</td>
    <td>Verify ping to XOS sync vtn container </td>
    <td>test_xos_sync_vtn_container_ping</td>
    <td>Bring up XOS sync vrn container
Ping to the container </td>
    <td>Ping should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_27</td>
    <td>Verify listening ports on XOS sync vtn container </td>
    <td>test_xos_sync_vtn_container_listening_ports</td>
    <td>Bring up XOS sync vtn container
Grep all the open ports on the container </td>
    <td>Ports status should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_28</td>
    <td>Verify XOS sync onboarding container status </td>
    <td>test_xos_sync_onboarding_container_status</td>
    <td>Bring up XOS sync onboarding container </td>
    <td>Container status should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_29</td>
    <td>Verify ping to XOS sync onboarding container</td>
    <td>test_xos_sync_onboarding_container_ping </td>
    <td>Bring up XOS sync onboarding container
Ping to the container </td>
    <td>Ping to the container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_30
</td>
    <td>Verify listening ports on XOS sync onboarding container </td>
    <td>test_xos_sync_onboarding_container_listening_ports</td>
    <td>Bring up XOS sync onboarding container
Grep all the open ports on container </td>
    <td>All the port status should be  Up</td>
    <td></td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_31</td>
    <td>Verify XOS post login api </td>
    <td>test_xos_api_post_login</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/login/
</td>
    <td>Login to post login XOS api should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_32</td>
    <td>Verify get utils port forwarding XOS api </td>
    <td>test_xos_api_get_utils_port_forwarding</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/portforwarding/</td>
    <td>Get operation of the api should be success
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>XOS_33













</td>
    <td>Verify get utils slices plus XOS api</td>
    <td>test_xos_api_get_utils_slices_plus</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/slicesplus/</td>
    <td>Get operation of the api should be success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_34</td>
    <td>Verify get utils synchronizer XOS api</td>
    <td>test_xos_api_get_utils_synchronizer</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/synchronizer/</td>
    <td>Get operation of the api should be success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XS_35










</td>
    <td>Verify get utils onboarding XOS api</td>
    <td>test_xos_api_get_utils_onboarding_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/onboarding/service/ready</td>
    <td>Get operation of the api should be success
</td>
    <td>







</td>
  </tr>
  <tr>
    <td>XOS_36</td>
    <td>Verify post utils tosca recipe XOS api </td>
    <td>test_xos_api_post_utils_tosca_recipe</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/tosca/run/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_37</td>
    <td>Verify get utils ssh keys XOS api</td>
    <td>test_xos_api_get_utils_ssh_keys</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/sshkeys/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_38</td>
    <td>Verify get tenant all subscribers XOS api</td>
    <td>test_xos_api_get_tenant_all_subscribers</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_39</td>
    <td>Verify get tenant subscriber details XOS api </td>
    <td>test_xos_api_get_tenant_subscribers_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_40</td>
    <td>Verify get
Tenant subscriber  delete XOS api</td>
    <td>test_xos_api_get_tenant_subscriber_delete</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_41</td>
    <td>Verify get tenant subscriber feature details XOS api </td>
    <td>test_xos_api_get_tenant_subscribers_feature_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_42</td>
    <td>Verify get tenant read subscriber feature uplink speed XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_uplink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/</td>
    <td>Opening url should return success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_43</td>
    <td>Verify tenant put update subscribers feature uplink speed XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_uplink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_44</td>
    <td>Verify get tenant read subscriber download speed XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_downlink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_45</td>
    <td>Verify tenant put update subscribers feature downlink speed XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_downlink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_46</td>
    <td>Verify get tenant read subscribers feature cdn XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_cdn</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/</td>
    <td>Opening url should return success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_47</td>
    <td>Verify tenant put update subscribers feature cdn XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_cdn</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_48</td>
    <td>Verify get tenant read subscribers feature uverse XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_uverse</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_49</td>
    <td>Verify tenant put update subscribers feature uverse XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_uverse</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_50</td>
    <td>Verify get tenant read subscribers features status XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_featurers_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_51</td>
    <td>Verify tenant put update subscribers features status XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_52</td>
    <td>Verify tenant get all  ruckroll</td>
    <td>test_xos_api_tenant_get_all_truckroll </td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_53</td>
    <td>Verify tenant post create truckroll XOS api</td>
    <td>test_xos_api_tenant_post_create_truckroll</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_54</td>
    <td>Verify tenant get truckroll details XOS api</td>
    <td>test_xos_api_tenant_get_truckroll_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_55</td>
    <td>Verify tenatn delete truckroll XOS api</td>
    <td>test_xos_api_tenant_delete_trucroll</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_56</td>
    <td>Verify tenant get all volt XOS api</td>
    <td>test_xos_api_tenant_get_all_volt</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_57</td>
    <td>Verify tenant post create vOLT XOS api</td>
    <td>test_xos_api_tenant_post_create_vOLT</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_58</td>
    <td>Verify tenant get volt details XOS api</td>
    <td>test_xos_api_tenant_get_volt_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_59</td>
    <td>Verify tenant get all onos apps XOS api</td>
    <td>test_xos_api_tenant_get_all_onos_apps</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/onos/app/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_60</td>
    <td>Verify service get all example service XOS api</td>
    <td>test_xos_api_service_get_all_example_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/exampleservice/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_61</td>
    <td>Verify service get all onos service XOS api </td>
    <td>test_xos_api_service_get_all_onos_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/onos/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_62</td>
    <td>Verify service get all vsg XOS api</td>
    <td>test_xos_api_service_get_all_vsg</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/exampleservice/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_63</td>
    <td>Verify core get all deployements XOS api</td>
    <td>test_xos_api_core_get_all_deployments</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/onos/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_64</td>
    <td>Verify core post create deployments XOS api</td>
    <td>test_xos_api_core_post_create_deployments</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/vsg/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_65</td>
    <td>Verify core get deployment details XOS api</td>
    <td>test_xos_api_core_get_deployment_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_66</td>
    <td>Verify core delete deployment XOS api</td>
    <td>test_xos_api_core_delete_deployment</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_67</td>
    <td>Verify core get all flavours XOS api</td>
    <td>test_xos_api_core_get_all_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_68</td>
    <td>Verify core post create flavors XOS api</td>
    <td>test_xos_api_core_post_create_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>
XOS_69</td>
    <td>Verify core get flavor details XOX api </td>
    <td>test_xos_api_core_get_flavor_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_70</td>
    <td>Verify core delete flavors XOS api</td>
    <td>test_xos_api_core_delete_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_71</td>
    <td>Verify core get all instances XOS api</td>
    <td>test_xos_api_core_get_all_instances</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_72</td>
    <td>Verify core post create instances XOS api</td>
    <td>test_xos_api_core_post_create_instances</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/?no_hyperlinks=1</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_73</td>
    <td>Verify core get instance details XOS api</td>
    <td>test_xos_api_core_get_instance_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/</td>
    <td>
Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_74</td>
    <td>Verify core delete instance XOS api</td>
    <td>test_xos_api_core_delete_instance</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_75</td>
    <td>Verify core get all nodes XOS api</td>
    <td>test_xos_api_core_get_all_nodes</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/nodes/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_76</td>
    <td>Verify core get all services XOS api</td>
    <td>test_xos_api_core_get_all_services</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_77</td>
    <td>Verify core post create service XOS api</td>
    <td>test_xos_api_core_post_create_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_78</td>
    <td>Verify core get service details XOS api</td>
    <td>test_xos_api_core_get_service_details</td>
    <td>'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_79</td>
    <td>Verify core delete service XOS api</td>
    <td>test_xos_api_core_delete_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_80</td>
    <td>Verify core get all sites XOS api</td>
    <td>test_xos_api_core_get_all_sites</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_81</td>
    <td>Verify core get site details XOS api</td>
    <td>test_xos_api_core_get_site_details</td>
    <td>'https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_82</td>
    <td>Verify core get all slices XOS api</td>
    <td>test_xos_api_core_get_all_slices</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/slices/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_83</td>
    <td>Verify core get all users XOS api</td>
    <td>test_xos_api_core_get_all_users</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/users/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
</table>
