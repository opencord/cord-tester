# CORD POD Test-cases

This is a rough sketch of planned test-cases, organized in areas.
Regard it as a wish-list.
Feel free to contribute to the list and also use the list to get idea(s) where test
implementation is needed.

## Test-Cases

Test-cases are organized in the following categories:

* Deployment tests
* Baseline readiness tests
* Functional end-user tests
* Transient, fault, HA tests
* Scale tests
* Security tests
* Soak tests

Some test-cases may re-use other test-cases as part of more complex scenarios.

### Deployment Tests

The scope and objective of these test-cases is to run the automated deployment process on a "pristine" CORD POD and verify that at the end the system gets into a known (verifiable) baseline state, as well as that the feedback from the automated deployment process is consistent with the outcome (no false positives or negatives).

Positive test-cases:

* Bring-up and verify basic infrastructure assumptions
  * Head-end is available, configured correctly, and available for software load
  * Compute nodes are available and configured correctly, and available for software load
* Execute automated deployment of CORD infrastructure and verify baseline state. Various options needs to be supported:
  * Single head-node setup (no clustering)
  * Triple-head-node setup (clustered)
  * Single data-plane up-link from servers (no high availability)
  * Dual data-plane up-link from servers (with high availability)

Negative test-cases:

* Verify that deployment automation detects missing equipment
* Verify that deployment notifies operator of missing configuration
* Verify that deployment automation detects missing cable
* Verify that deployment automation detects mis-cabling of fabric and provides useful feedback to remedy the issue
* Verify that deployment automation detects mis-cabling of servers and provides useful feedback to remedy the issue

### Baseline Readiness Tests

* Verify API availability (XOS, ONOS, OpenStack, etc.)
* Verify software process inventory (of those processes that are covered by the baseline bring-up)

### Functional End-User Tests

Positive test-cases:

* Verify that a new OLT can be added to the POD and it is properly initialized
* Verify that a new ONU can be added to the OLT and it becomes visible in the system
* Verify that a ONU port going down triggers unprovisioning of service for a subscriber
* Verify that a new RG can authenticate and gets admitted to the system (receives an IP address, deployment dependent)
* Verify that the RG can access the Intranet and the Internet
* Verify that the RG receives periodic IGMP Query messages and forwards to set top boxes.
* Verify that the RG can join a multicast channel and starts receiving bridge flow
* Verify that the RG, after joining, starts receiving multicast flow within tolerance interval
* Verify that the RG can join multiple multicast streams simultaneously
* Verify that the RG receives periodic IGMP reports

Complex test-cases:

* Measure channel surfing experience
* Replacing RG for existing subscriber
* Moving existing subscriber to a new address (same RG, new location)
* Rate at which new subscribers can be added to / removed from the system

Negative test-cases:

* Verify that a subscriber that is not registered cannot join the network
* Verify that a subscriber RG cannot be added unless it is on the pre-prescribed port (OLT/ONU port?)
* Verify that a subscriber that has no Internet access cannot reach the Internet
* Verify that a subscriber with limited channel access cannot subscribe to disabled/prohibited channels
* Verify that a subscriber identity cannot be re-used at a different RG (no two RGs
with the same certificate can ever be logged into the system)

### Transient, fault, HA Tests

In this block, test-cases should cover the following scenarios:

Hardware disruption scenarios cycling scenarios:

In the following scenarios, in cases of non-HA setups, the system shall at least recover after the hardware component is restored. In HA scenarios, the system shall be able to ride these scenarios through without service interrupt.

* Power cycling OLT
* Power cycling ONU
* Re-starting RG
* Power cycling any server (one at a time)
* Power cycling any fabric switch
* Power cycling any of the VMs
* Power cycling management switch
* Replacing a server-to-leaf cable
* Replacing a leaf-to-spine cable

In HA scenarios, the following shall result in only degraded service, but not loss of service:

* Powering off a server (and keep it powered off)
* Powering off a spine fabric switch
* Powering off a leaf fabric switch
* Removing a server-to-leaf cable (emulating DAC failure)
* Removing a leaf-to-spine cable (emulating DAC failure)
* Powering off management switch
* Powering back each of the above

Process cycling scenarios:

* Restarting any of the processes
* Killing any of the processes (system shall recover with auto-restart)
* Killing and restoring containers
* Relocation scenarios [TBD]

Additive scenarios:

* Add a new spine switch to the system
* Add a new compute server to the system
* Add a new head node to the system

### Scale Tests

Test load input dimensions to track against:

* Number of subscribers
* Number of routes pushed to CORD POD
* Number of NBI API sessions
* Number of NBI API requests
* Subscriber channel change rate
* Subscriber aggregate traffic load to Internet

In addition to healthy operation, the following is the list contains what needs to be measured quantitatively, as a function of input load:

* CPU utilization per each server
* Disk utilization per each server
* Memory utilization per each server
* Network utilization at various capture points (fabric ports to start with)
* Channel change "response time" (how long it takes to start receiving bridge traffic as well as real multicast feed)
* Internet access round-trip time
* CPU/DISK/Memory/Network trends in relationship to number of subscribers
* After removal of all subscribers system should be "identical" to the new install state (or reasonably similar)

### Security Tests

The purpose of these tests is to detect vulnerabilities across the various surfaces of CORD, including:

* PON ports (via ONU ports)
* NBI APIs
* Internet up-link
* CORD POD-Local penetration tests
  * Via patch cable into management switch
  * Via fabric ports
  * Via unused NIC ports of server(s)
  * Via local console (only if secure boot is enabled)

Tests shall include:

* Port scans on management network: only a pre-defined list of ports shall be open
* Local clustering shall be VLAN-isolated from the management network
* Qualys free scan
* SSH vulnerability scans
* SSL certificate validation

[TBD: define more specific test scenarios]

In addition, proprietary scans, such as Nessus Vulnerability Scan will be performed prior to major releases by commercial CORD vendor Ciena.


### Soak Tests

This is really one comprehensive multi-faceted test run on the POD, involving the following steps:

Preparation phase:

1. Deploy system using the automated deployment process
1. Verify baseline acceptance
1. Admit a preset number of RGs
1. Subscribe to a pre-configured set of multicast feeds
1. Start a nominal Internet access load pattern on each RG
1. Optionally (per test config): start background scaled-up load (dpdk-pktgen based)
1. Capture baseline resource usage (memory, disk utilization per server, per vital process)

Soak phase (sustained for a preset time period (8h, 24h, 72h, etc.):

1. Periodically monitor health of ongoing sessions (emulated RGs happy?)
1. Periodically test presence of all processes
1. Check for stable process ids (rolling id can be a sign of a restarted process)
1. Periodically capture resource usage, including:
   * CPU load
   * process memory use
   * file descriptors
   * disk space
   * disk io
   * flow table entries in soft and fabric switches

Final check:

1. Final capture of resource utilization and health report


## Baseline Acceptance Criteria

The baseline acceptance is based on a list of criteria, including:

On all servers involved in the POD:

* Verify BIOS settings (indirectly)
* Verify kernel boot options
* Verify OS version
* Verify kernel driver options for NICs (latest driver)
* Verify kernel settings
* Verify software inventory (presence and version) of following as applicable
  * DPDK version
  * ovs version
  * etc.
