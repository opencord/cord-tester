**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Test Cases (Implemented and Planned) : **

**Platform Tests Test Cases (Implemented and Planned) : **


**Docker engine and docker.py should be installed on test host.**

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
    <td>Plat_1</td>
    <td>Verify the docker status</td>
    <td></td>
    <td></td>
    <td>If its running, docker status should return true. </td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_2</td>
    <td>Pull (default) "onosproject/onos:latest" image</td>
    <td></td>
    <td></td>
    <td>Pulling should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_3</td>
    <td>Create new container for onos</td>
    <td></td>
    <td></td>
    <td>Container should get successfully created.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_4</td>
    <td>Get IP address on ONOS containers</td>
    <td></td>
    <td></td>
    <td>Container IPs should get listed.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_5</td>
    <td>check standalone apps status</td>
    <td></td>
    <td></td>
    <td>"drivers" app should be in ACTIVE state AND all builtin apps in "INSTALLED" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_6</td>
    <td>Activate "proxyarp" and "fwd" apps and check apps status</td>
    <td></td>
    <td></td>
    <td>It should be in "ACTIVE" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_7</td>
    <td>Deactivate "proxyarp" and "fwd" apps and check app status</td>
    <td></td>
    <td></td>
    <td>It should be in "Installed" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_8</td>
    <td>ONOS exceptions check</td>
    <td></td>
    <td></td>
    <td>After test, there should be no logs for exceptions.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_9</td>
    <td>post-test clean env</td>
    <td></td>
    <td></td>
    <td>No containers and images should be left.</td>
    <td></td>
  </tr>
</table>
