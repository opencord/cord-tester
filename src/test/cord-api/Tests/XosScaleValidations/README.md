# XOS Scale test

This test suite is still under active developemnt so some
manual steps are needed in order to execute it.

## Setup the test

There a `setup-venv.sh` script in `../..`, use that.

In order to connect to kafka, find the correct IP with:

```bash
kubectl get svc | grep cord-platform-kafka
```

and replace it in `xos-scale-att-workflow.robot` on line 16: 

```python
${cord_kafka}           10.152.183.118
```

## Run the test

Tests can executed via the cli with this command:

```bash
robot --variable num_olts:10 --variable num_onus:1 --variable num_pon_ports:10  xos-scale-att-workflow.robot
```

## Known issues

When running the test with multiple onus per pon port some errors occur. Still need to debug those.