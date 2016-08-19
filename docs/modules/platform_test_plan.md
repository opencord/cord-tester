**Platform Test Plan**

**Platform Test Cases (Implemented and Planned) : **

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
