# **Cord-Tester**

**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Metrics Test Cases (Implemented and Planned) : **


**1. Install CollectD plugin which is in charging of reporting all metric values to ONOS through REST API.**

**2. Install ONOS and activate CPMan application to receive system metrics from CollectD**.

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Functio Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Metrics_1</td>
    <td>Collector- CPU metrics</td>
    <td></td>
    <td>POST /collector/cpu_metrics</td>
    <td>Collects CPU metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_2</td>
    <td>Collector- network I/O metrics</td>
    <td></td>
    <td>POST /collector/network_metrics</td>
    <td>Collects network I/O metrics include in/out-bound packets/bytes statistics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_3</td>
    <td>Collector-disk I/O metrics</td>
    <td></td>
    <td>POST /collector/disk_metrics</td>
    <td>Collects disk I/O metrics include read and write bytes</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_4</td>
    <td>Collector-system info</td>
    <td></td>
    <td>POST /collector/system_info</td>
    <td>Collects system information</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_5</td>
    <td>Collector-memory metrics</td>
    <td></td>
    <td>POST /collector/memory_metrics</td>
    <td>Collects memory metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_6</td>
    <td>Control-Memory metrics</td>
    <td></td>
    <td>GET /controlmetrics/memory_metrics</td>
    <td>List memory metrics of all network resources</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_7</td>
    <td>Control-message metrics</td>
    <td></td>
    <td>GET /controlmetrics/messages</td>
    <td>List control message metrics of all devices</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_8</td>
    <td>Control-message metrics</td>
    <td></td>
    <td>GET /controlmetrics/messages/{deviceId}</td>
    <td>List control message metrics of a given device</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_9</td>
    <td>Control-CPU metrics</td>
    <td></td>
    <td>GET /controlmetrics/cpu_metrics</td>
    <td>List CPU metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_10</td>
    <td>Control-disk metrics</td>
    <td></td>
    <td>GET /controlmetrics/disk_metrics</td>
    <td>List disk metrics of all disk resources</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_11</td>
    <td>Verify the intent installation latency</td>
    <td></td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.                                      3.Install a single intent from the CLI
 </td>
    <td>Command :
onos:intents-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_12</td>
    <td>Verify the intent installation latency in JSON format</td>
    <td></td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.
3. Install a single intent from the CLI</td>
    <td>Command :
onos:intents-events-metrics --json
Should show the information in json format.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_13</td>
    <td>Listing ONOS intent events</td>
    <td></td>
    <td>onos> onos:intents-events</td>
    <td>It should list 100 intent related events.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_14</td>
    <td>Verify topology event metrics</td>
    <td></td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_15</td>
    <td>Verify topology event metrics</td>
    <td></td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics --json
Should show the information in json format.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_16</td>
    <td>Listing topology events</td>
    <td></td>
    <td>onos> onos:topology-events</td>
    <td>This should list last 100 topology events.</td>
    <td></td>
  </tr>
</table>
