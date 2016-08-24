**Authentication Test Plan**

**Authentication Test Cases (Implemented and Planned) : **

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
</table>

