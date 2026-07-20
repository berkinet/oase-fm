# oase-fm

Local Python control for the OASE InScenio FM-Master EGC.

The project provides a reusable `oase_fm` module and a small command-line
interface for reading FM-Master outlet and attached EGC state, changing outlet
and EGC settings, discovering EGC devices, reading EGC RPM and wattage sensors,
and issuing low-level RDM requests.

## Requirements

- Python 3.9 or newer
- An OASE FM-Master EGC reachable on the local network
- The app password for the controller

Install the Python dependency:

```bash
python3 -m pip install -r requirements.txt
```

Set the controller password without storing it in the repository:

```bash
export OASE_PASSWORD='your-app-password'
```

## Status

Read the FM-Master outlets, controller Wi-Fi RSSI in dBm, and attached EGC
state:

```bash
python3 oase_control.py --device-ip 192.168.5.176 --local-ip 192.168.5.10 status
```

For EGC pumps that expose standard RDM telemetry sensors, the EGC status also
includes the current RPM and power consumption in watts. Sensor numbers are
discovered from the device definitions rather than assumed, and unsupported
telemetry is reported as unavailable.

## Changing state

All state changes use `set`. Multiple assignments are separated by commas:

```bash
python3 oase_control.py --device-ip 192.168.5.176 --local-ip 192.168.5.10 set 4 on, 3 off, dimmer 128
```

The single attached EGC device can be controlled in the same command context:

```bash
python3 oase_control.py --device-ip 192.168.5.176 --local-ip 192.168.5.10 set egc on, power 50
```

Use `python3 oase_control.py --help` for the EGC discovery and raw RDM
interfaces. `oase_control_rdm.py` remains available as a compatible entry
point.

## Tests

```bash
python3 -m unittest -v
```

## Acknowledgement

The working UDP/TLS connection, authentication, live-scene reading, and socket
control implementation was based on
[mr-suw/ioBroker.oasecontrol](https://github.com/mr-suw/ioBroker.oasecontrol),
published under the MIT License. Additional EGC/RDM behavior was derived from
the OASE application libraries and tested against local hardware.
