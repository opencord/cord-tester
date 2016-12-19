**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**? Functional Testing**

**? Regression testing for CORD related component development**

**? Acceptance testing of a deployed CORD POD**

**? Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**netCondition Test Cases (Implemented and Planned) :

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
    <td>netCondition_1</td>
    <td>Verify netCondition for delay between igmp join and data</td>
    <td>test_netCondition_with_delay_between_igmp_join_and_data_recv</td>
    <td>Add delay between igmp join and data traffic </td>
    <td>If delay more than igmp group expiry time, client should not receive traffic </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_2</td>
    <td>Verify netCondition for delay between igmp data and join </td>
    <td>test_netCondition_with_delay_between_data_recv_and_igmp_join</td>
    <td>Initiate igmp data traffic first and after some delay send igmp join </td>
    <td>Join should receive data </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_3</td>
    <td>Verify netCondition for delay between igmp leave and data</td>
    <td>test_netCondition_with_delay_between_igmp_leave_and_data</td>
    <td>Add delay between igmp leave and  data  traffic </td>
    <td>Client should not receive traffic </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_4</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_positive_IdReq_and_tlsHelloReq</td>
    <td>Add delay between tls Id and Hello requests. Positive case  </td>
    <td>Authentication should get successful </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_5</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_IdReq_and_tlsHelloReq </td>
    <td>Add delay between tls Id and Hello requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_6</td>
    <td>Verify netCondition for delay between tls Hello and Cert request packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_tlsHelloReq_and_eapTlsCertReq </td>
    <td>Add delay between tls Hello and cert requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_7</td>
    <td>Verify netCondition for delay between tls Cert Req and Change cipher spec packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_TlsCertReq_and_TlsChangeCipherSpec </td>
    <td>Add delay between tls cert req and change cipher spec  requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_8</td>
    <td>Verify netCondition for delay between tls IdReq and Hello Req packets exchange with no cert </td>
    <td>test_netCondition_in_eap_tls_with_no_cert_and_delay_between_IdReq_and_HelloReq </td>
    <td>Add delay between tls Id and Hello requests with no cert </td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_9</td>
    <td>Verify netCondition for delay between tls Hello Req and CertReq packets exchange with no certificates</td>
    <td>test_netCondition_in_eap_tls_with_delay_and_no_cert_between_tlsHelloReq_and_eapTlsCertReq </td>
    <td>Add delay between tls Hello and Cert Requests with no certificates </td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_10</td>
    <td>Verify netCondition for delay between tls CertReq and change cipher spec packets exchange with no certificates </td>
    <td>test_netCondition_in_eap_tls_with_delay_and_no_cert_between_TlsCertReq_and_TlsChangeCipherSpec</td>
    <td>Add delay between tls Cert adn change cipher spec Requests with no certificates</td>
    <td>Authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_11</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange with invalid certificates</td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_IdReq_and_HelloReq</td>
    <td>Add delay between tls ID and Hello requests with invalid certificates</td>
    <td>Authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_12</td>
    <td>Verify netCondition for delay between tls HelloReq and CertReq packets exchange with invalid certificates </td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_tlsHelloReq_and_eapTlsCertReq</td>
    <td>Add delay between tls Hello and Cert requests with invalid certificates</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_13</td>
    <td>Verify netCondition for delay between tls CertReq and change cipher spec packets exchange with invalid certificates </td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_delay_between_TlsCertReq_and_TlsChangeCipherSpec</td>
    <td>Add delay between tls Cert and change cipher spec requests with invalid certificates</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_14</td>
    <td>Verify netCondition in multiple tls requests with delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_multiple_eap_tls_requests_with_delay_between_IdReq_and_HelloReq</td>
    <td>Add delay between tls ID and Hello  requests for multiple tls clients </td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_15</td>
    <td>Verify netCondition in multiple tls requests for delay between tls packets exchange</td>
    <td>test_netCondition_with_multiple_authentication_and_delay_between_complete_authentication</td>
    <td>Add delay between tls authentication packets for multiple tls clients</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_16</td>
    <td>Verify netCondition delay for every 100 tls burst when multiple tls requests sent</td>
    <td>test_netCondition_with_multiple_authentication_and_delay_between_every_100_tls_burst</td>
    <td>Add delay between every 100 tls burst packets for multiple tls clients</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_17</td>
    <td>Verify netCondition for delay between  mac flow and traffic </td>
    <td>test_netCondition_with_delay_between_mac_flow_and_traffic</td>
    <td>Add delay between mac flow and data </td>
    <td>Flow traffic should forward to destination port  </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_18</td>
    <td>Verify netCondition for delay between  ip flow and traffic</td>
    <td>test_netCondition_with_delay_between_ip_flow_and_traffic</td>
    <td>Add delay between ip flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_19</td>
    <td>Verify netCondition for delay between  tcp port flow and traffic</td>
    <td>test_netCondition_with_delay_between_tcp_port_flow_and_traffic</td>
    <td>Add delay between tcp port flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_20</td>
    <td>Verify netCondition for delay below udp port flow and traffic</td>
    <td>test_netCondition_with_delay_between_udp_port_flow_and_traffic</td>
    <td>Add delay between udp port flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_21</td>
    <td>Verify netCondition for delay between multiple igmp joins and data </td>
    <td>netCondition_with_delay_between_multiple_igmp_joins_and_data</td>
    <td>Add delay between multiple igmp joins and data </td>
    <td>If igmp group not expired, client should receive  data traffic </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_22</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data for multiple subscribers </td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_multiple_subscribers</td>
    <td>Add delay between multiple igmp joins and data for multiple subscribers </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_23</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data for multiple subscribers with low multicast data rate </td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_multiple_subscribers_with_low_multicast_data_rate</td>
    <td>Add delay between multiple igmp joins and data for multiple subscribers with low multicast data rate </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_24</td>
    <td>Verify netCondition for delay between multiple igmp joins and data for same subscribers</td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_same_subscriber</td>
    <td>Add delay between multiple igmp joins and data for same subscriber</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_25</td>
    <td>Verify netCondition for delay between same igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_delay_between_same_igmp_joins_and_data_from_multiple_subscriber</td>
    <td>Add delay between join and data for same group from multiple subscribers </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_26</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data with same source list  for multiple subscribers</td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_same_sourcelist_for_multiple_subscriber</td>
    <td>Add delay between join and data for same group from multiple subscribers for same source list</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_27</td>
    <td>Verify netCondition for throttle between multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_throttle_between_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Add Throttle between igmp join and data sent from multiple subscribers</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_28</td>
    <td>Verify netCondition for invalid igmp type  multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_igmp_type_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send invalid type multiple igmp joins  and data to groups from multiple subscribers </td>
    <td>Igmp joins should not registered and clients  should not receive data traffic </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_29</td>
    <td>Verify netCondition for invalid igmp ecord type multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_record_type_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send record type multiple igmp joins  and data to groups from multiple subscribers</td>
    <td>Igmp joins should not registered and clients  should not receive data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_30</td>
    <td>Verify netCondition for invalid ttl and multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_ttl_and_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send invalid ttl type multiple igmp joins  and data to groups from multiple subscribers</td>
    <td>Igmp joins should not registered and clients  should not receive data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_31</td>
    <td>Verify netCondition for tls out of order packets exchange between client and server hello </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_exchanges_between_serverHello_and_client_packet</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_32</td>
    <td>Verify netCondition for tls out of order packets exchange in tls Cert Req packets</td>
    <td>test_netCondition_in_multiple_eap_tls_session_with_out_of_order_exchanges_in_eapTlsCertReq_packets</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_33</td>
    <td>Verify netCondition for tls out of order packets exchange in tls change cipher spec packets </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_eapTlsChangeCipherSpec_packets</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_34</td>
    <td>Verify netCondition for multiple tls sessions dropping Hello request</td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsHelloReq_packets</td>
    <td>Initiate tls authentication from client and drop server hello request packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_35</td>
    <td>Verify netCondition for multiple tls sessions dropping change ciper spec packet </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsChangeCipherSpec_packets</td>
    <td>Initiate tls authentication from client and drop server change cipher spec request packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_36</td>
    <td>Verify netCondition for invalid eapol version in client authentication packets </td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_version_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client with invalid eapol version in client packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_37</td>
    <td>Verify netCondition for invalid tls type in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_tls_type_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls type in client packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_38</td>
    <td>Verify netCondition for invalid eapol type ID in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_type_ID_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls type ID in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_39</td>
    <td>Verify netCondition for invalid eapol response field in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_response_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol  response field in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_40</td>
    <td>Verify netCondition for invalid eap content type in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_eap_content_type_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls content type in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_41</td>
    <td>Verify netCondition for invalid tls version in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_tls_version_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls version in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_42</td>
    <td>Verify netCondition for invalid ciper suite field in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_tls_cipher_suite_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol cipher suite in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_43</td>
    <td>Verify netCondition for identifier field mismatch in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_id_mismatch_in_identifier_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client with mismatch in identifier field in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_44</td>
    <td>Verify netCondition for ID mismatch in client hello packet</td>
    <td>test_netCondition_in_eap_tls_with_id_mismatch_in_client_hello_auth_packet</td>
    <td>Initiate tls authentication from client with ID mismatch in client hello packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_45</td>
    <td>Verify netCondition for invalid handshake  type in client hello packet</td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_hello_handshake_type_auth_packet</td>
    <td>Initiate tls authentication from client with invalid handshake type in client hello packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_46</td>
    <td>Verify netCondition for invalid client certReq handhsake type in authentication packet</td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_cert_req_handshake_auth_packet</td>
    <td>Initiate tls authentication from client with invalid client cert request handshake in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_47</td>
    <td>Verify netCondition for client key exchange replace with server key exchange  in tls cleint authentication packets </td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_key_ex_replacing_server_key_ex</td>
    <td>Initiate tls authentication from client with client key exchange replaces server  key exchange in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_48</td>
    <td>Verify netCondition emulating tls client authentication without radius server </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_emulating_server_packets_without_radius_server_container</td>
    <td>Initiate tls authentication from client without radius server </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_49</td>
    <td>Verify netCondition for server eap tls id response packet drop </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_server_eapid_response_packet</td>
    <td>Initiate tls authentication from client and drop server eapid response packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_50</td>
    <td>Verify netCondition for  invalid tls eapid response packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_server_eapid_response_packet</td>
    <td>Initiate tls authentication from client  with invalid server eapid response packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_51</td>
    <td>Verify netCondition for server tls hello  packet drop</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_server_hello_packet</td>
    <td>Initiate tls authentication from client and drop server  hello response packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_52</td>
    <td>Verify netCondition for  invalid tls server hello packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_server_hello_packet</td>
    <td>Initiate tls authentication from client with invalid server hello packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_53</td>
    <td>Verify netCondition for dropping client certificate access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_54</td>
    <td>Verify netCondition for invalid  client certificate access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  with invalid server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_55</td>
    <td>Verify netCondition for dropping client certificate with 2nd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_with_2nd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop client certificate with 2nd fragment server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_56</td>
    <td>Verify netCondition for invalid client certificate with 2nd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_with_2nd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  invalid client certificate with 2nd fragment server access challenge  packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_57</td>
    <td>Verify netCondition for dropping client certificate with 3rd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_with_3rd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop client certificate with 3rd  fragment server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_58</td>
    <td>Verify netCondition for invalid client certificate with 3rd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_with_3rd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  with invalid client certificate 3rd  fragment server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_59</td>
    <td>Verify netCondition for dropping cipher suite request server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_cipher_suite_request_server_packet</td>
    <td>Initiate tls authentication from client and drop cipher suite requests server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_60</td>
    <td>Verify netCondition for invalid cipher suite request server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_cipher_suite_request_server_packet</td>
    <td>Initiate tls authentication from client  with invalid cipher suite server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_61</td>
    <td>Verify netCondition for dropping access accept  server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_access_accept_server_packet</td>
    <td>Initiate tls authentication from client and drop access accept  server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_62</td>
    <td>Verify netCondition for invalid access accept  server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_access_accept_server_packet</td>
    <td>Initiate tls authentication from client  with invalid access accept server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
</table>


