# XOS Scale test

This test suite is still under active developemnt so some
manual steps are needed in order to execute it.

## Setup the test

There a `setup-venv.sh` script in `../..`, use that.

In order to connect to kafka, find the correct IP with:

```bash
kubectl get svc | grep cord-platform-kafka
```

It will be needed while running the command

## Run the test

Tests can executed via the cli with this command:

```bash
robot --variable xos_chameleon_url:127.0.0.1 \
--variable xos_chameleon_port:30006 \
--variable cord_kafka:10.152.183.118 \
--variable num_olts:10 \
--variable num_onus:1 \
--variable num_pon_ports:10 \
xos-scale-att-workflow.robot
```
