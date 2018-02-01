# Steps to test VOLTHA using CORD-TESTER with PONSIM ONU & OLT

## Install CORD-TESTER

```shell
~$ git clone https://github.com/opencord/cord-tester.git
~$ cd cord-tester
~$ cd /cord-tester/src/test/setup/
~$ sudo bash prerequisites.sh
~$ sudo ./cord-test.py build all
```

## Install VOLTHA, following this link

```shell
https://github.com/opencord/voltha/blob/master/BUILD.md
```

## Get into setup directory of cord tester

```shell
$cord-tester/src/test/setup/
```

## Please make sure of VOLTHA location in manifest-ponsim.json

```shell
For e.g "voltha_loc" : "/home/ubuntu/cord/incubator/voltha"
```

## Run following command to clean up previous installs

```shell
sudo ./cord-test.py cleanup -m manifest-ponsim.json
```

## Run following command to setup the testing stage with ponsim OLT & ONU

This makes a setup of cord-test container (cord-tester1) and hooks up pon
interface to UNI port of PONSIM ONU.***

```shell
sudo ./cord-test.py setup -m manifest-ponsim.json
```

## Now run following command to provision the OLT & ONU and run cord subscriber test

```shell
sudo ./cord-test.py run -m manifest-ponsim.json -t cordSubscriber:subscriber_exchange.test_cord_subscriber_voltha
```

* This will start the cord tester to run cord subscriber test
    * CORD Subcriber emulation with AAA TLS & IGMP subscriber channel surfing
      test for you.  Have a look for steps followed to test in output log of
      test run.
    * AAA TLS test will validate exchange of multiple messages of eap, hello,
      certificates, verify data between cord tester TLS client and Radius
      Server with a validation of flows installed in OLT & ONU
    * IGMP test will surf channels joining a group and validating the multicast
      traffic received on it with the flows installed

## Now you can manually also validate on voltha cli for confirmation

```shell
 ~$(voltha)devices
 ~$(voltha)device <OLT deviceid>
 ~$(device OLT deviceid)flows  <--- for ONU
 ~$(device OLT deviceid)ports  <--- For NNI & PON Ports

 ~$(voltha)device <ONU deviceid>
 ~$(device ONU deviceid)flows  <--- for ONU
 ~$(device ONU deviceid)ports  <--- for UNI & PON Ports
```


