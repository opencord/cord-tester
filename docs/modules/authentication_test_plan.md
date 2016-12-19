**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**Functional Testing**

**Regression testing for CORD related component development**

**Acceptance testing of a deployed CORD POD**

**Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Authentication Test Cases (Implemented and Planned) : **


** **

**Set up for EAP-TLS :**

**-------------------------**

**1. ****ea.conf file  (**

**          in eap section  default_eap_type = tls **

**          in gtc section comment the #auth_type = EAP }**

** **

**2. TLS Client Certification PEM file. (File name - inno-dev-ca-certificate..pem) .**

**3. Copy and past Client crt in server installed  CA.crt file. (File name -inno-dev-ca-certificate.crt)   **

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
    <td>Auth_1</td>
    <td>Verify EAP-MD5 authentication </td>
    <td> test_eap_md5</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response with identity.
3. Send EAP response with MD5 challenge</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP success message should be seen.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_2</td>
    <td>Verify EAP-MD5 authentication with wrong password</td>
    <td>test_eap_md5_wrg_password</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response.
3. Send EAP response with MD5 challenge with wrong password</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP failure message should be seen.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_3</td>
    <td>Verify EAP-MD5 authentication with wrong challenge</td>
    <td> </td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response.
3. Send EAP response with MD5 challenge with wrong challenge</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP failure message should be seen.
 </td>
    <td>To Be implemented</td>
  </tr>
  <tr>
    <td>Auth_4</td>
    <td>Verify EAP-TLS authentication</td>
    <td>test_eap_tls</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send Client Hello TLS Certificate.
5. Send Client TLS Finished</td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Got change cipher request from server
5. EAP-TLS success message should be seen.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_5</td>
    <td>Verify EAP-TLS authentication with empty TLS client certification</td>
    <td>test_eap_tls_noCrt</td>
    <td>1. Send EAPOL start message from the client
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send an empty Client Hello TLS Certificate
 </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_6</td>
    <td>Verify EAP-TLS authentication with Invalid client certification</td>
    <td>test_eap_tls_InvalidCrt</td>
    <td>1. Send EAPOL start message from the client .
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send an invalid Client Hello TLS Certificate
 </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out. </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_7</td>
    <td>Verify EAP-TLS authentication with self signed client certification</td>
    <td>test_eap_tls_Self_Signed_Crt</td>
    <td>1. Send EAPOL start message from the client .
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send Self signed Client Hello TLS Certificate. </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_8</td>
    <td>Verify EAP-TLS authentication with 2 RGs having the same valid TLS certificate </td>
    <td>test_eap_tls_2RGs_SameValid_Crt</td>
    <td>1.Let one RG start with EAPOL message using the valid TLS certificate.
2. Let 2nd RG start with EAPOL message using the same TLS certificate. </td>
    <td>Access reject message should be seen from ONOS or socket should get timed out.  </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_9</td>
    <td>Verify tls authentication fails with invalid session id </td>
    <td>test_eap_tls_invalid_session_id</td>
    <td>1. Initiate tls authentication process with invalid session id </td>
    <td>Authentication should get fail </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_10</td>
    <td>Verify random gmt_unit_time field in tls hello</td>
    <td>test_eap_tls_random_gmt_unix_time</td>
    <td>Initiate tla authentication process with gmt_unix_time value set to random value</td>
    <td>Authentication should get success if gmt_unix_time in within range </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_11</td>
    <td>Verify authentication with invalid content type in tls hello </td>
    <td>test_eap_tls_invalid_content_type</td>
    <td>Initiate tls authentication with invalid content type in tls hello</td>
    <td>Authentication should get failed </td>
    <td>Scapy tool filters invalid content type</td>
  </tr>
  <tr>
    <td>Auth_12</td>
    <td>Verify tls authentication with invalid fragment length field in tls record packet</td>
    <td>test_eap_tls_invalid_record_fragment_length</td>
    <td>Initiate tls authentication process with invalid fragment length in tls record </td>
    <td>Authentication should get failed </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_13</td>
    <td>Verify tls authentication with invalid id in identifier response packet </td>
    <td>test_eap_tls_with_invalid_id_in_identifier_response_packet</td>
    <td>Initiate tls authentication process with invalid id in identifier response packet </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_14</td>
    <td>Verify tls authentication with invalid id in client hello packet</td>
    <td>test_eap_tls_with_invalid_id_in_client_hello_packet</td>
    <td>Initiate tls authentication process with invalid id in client hello packet</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_15</td>
    <td>Verify tls authentication without sending client hello packet </td>
    <td>test_eap_tls_without_sending_client_hello</td>
    <td>Initiate tls authentication without sending client hello packet</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_16</td>
    <td>Verify tls authentication with app deactivated</td>
    <td>test_eap_tls_aaa_app_deactivate</td>
    <td>Initiate tls authentication with app deactivation </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_17</td>
    <td>Verify tls authentication with incorrect cipher suite length field</td>
    <td>test_eap_tls_incorrect_cipher_suite_length_field</td>
    <td>Initiate tls authentication with invalid cipher suite length field </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_18</td>
    <td>Verify tls authentication with incorrect compression method field length in  tls hello</td>
    <td>test_eap_tls_incorrect_compression_methods_length_field</td>
    <td>Initiate tls authentication with incorrect compression length field in tls hello </td>
    <td>Authentication should get failed </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_19</td>
    <td>Verify tls authentication with broadcast source mac</td>
    <td>test_eap_tls_invalid_source_mac_broadcast</td>
    <td>Initiate tls authentication process with client mac broadcast </td>
    <td>Authentication should get failed</td>
    <td>Fail
</td>
  </tr>
  <tr>
    <td>Auth_20</td>
    <td>Verify tls authentication with multicast source mac</td>
    <td>test_eap_tls_invalid_source_mac_multicast</td>
    <td>Initiate tls authentication process with client mac multicast </td>
    <td>Authentication should get failed</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>Auth_21</td>
    <td>Verify tls authentication with all 0’s source mac</td>
    <td>test_eap_tls_invalid_source_mac_zero</td>
    <td>Initiate tls authentication process with client mac all 0’s</td>
    <td>Authentication should get failed</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>Auth_22</td>
    <td>Verify tls authentication if radius server restarts in middle of auth process </td>
    <td>test_eap_tls_restart_radius_server</td>
    <td>Initiate tls authentication process and restart radius server in middle of  auth process </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_23</td>
    <td>Verify tls authentication with incorrect tls hello handshake type</td>
    <td>test_eap_tls_with_incorrect_handshake_type_client_hello</td>
    <td>Initiate tls authentication process with incorrect hello handshake type</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_24</td>
    <td>Verify tls authentication with incorrect tls hello handshake type certificate request </td>
    <td>test_eap_tls_with_incorrect_handshake_type_certificate_request</td>
    <td>Initiate tls authentication process with incorrect hello handshake type</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_25</td>
    <td>Verify tls authentication with incorrect tls hello tls record certificate request</td>
    <td>test_eap_tls_with_incorrect_tlsrecord_certificate_request</td>
    <td>Initiate tls authentication process with incorrect tls record certificate  request </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_26</td>
    <td>Verify tls authentication with invalid handshake length in client hello </td>
    <td>test_eap_tls_invalid_handshake_length_client_hello</td>
    <td>Initiate tls authentication with invalid  handshake length in client hello </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_27</td>
    <td>Verify tls authentication with client key exchange with server key exchange </td>
    <td>test_eap_tls_clientkeyex_replace_with_serverkeyex</td>
    <td>Initiate tls authentication process with client key exchange replaced with server key exchange </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_28</td>
    <td>Verify tls authentication for 1000 users </td>
    <td>test_eap_tls_1k_with_diff_mac</td>
    <td>Initiate tls authentication for 1000  clients</td>
    <td>Authentication should get success for  all 1000 clients </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_29</td>
    <td>Verify tls authentication for 5000 clients </td>
    <td>test_eap_tls_5k_with_diff_mac</td>
    <td>Initiate tls authentication for 5000  clients</td>
    <td>Authentication should get success for  all 5000 clients</td>
    <td>Pass</td>
  </tr>
</table>
