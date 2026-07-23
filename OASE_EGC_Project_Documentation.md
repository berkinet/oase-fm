# OASE EGC Reverse Engineering Project Documentation

## Documentation roadmap

1. EGC protocol overview
2. Supported devices
3. RDM device database
4. Known PIDs and sensors
5. Packet formats
6. Reverse-engineering notes
7. Indigo plugin architecture
8. Command-line utility
9. Contributing

## 1. EGC protocol overview

This project documents the OASE Easy Garden Control (EGC), now marketed as
**OASE Control (OC)**, communication system. It focuses on documenting the
local protocol, building open-source tools, and supporting an Indigo plugin.

The tested installation uses an FM-Master EGC Home as the network controller.
The controller is reached through OASE's ONet protocol over UDP and a
controller-initiated TLS callback. Intelligent downstream devices use RDM
messages carried inside ONet.

This is a local interoperability project. It does not attempt to activate,
emulate, or bypass OASE cloud services. Measurements marked for cloud
telemetry are investigated as locally available device data.

## 2. Supported devices

### Scope

The EGC device catalogue includes:

- Pumps
- Filters
- Lighting controllers
- Other intelligent downstream devices that communicate on the EGC bus

The catalogue excludes passive or infrastructure components that do not
present an EGC/RDM device identity:

- Power distribution outlets
- Extension cables
- Splitters
- Passive filter modules
- Accessories without an EGC interface

FM-Master controllers are outside the downstream EGC catalogue, but their
local ONet transport, discovery data, socket control, and callback connection
are documented because they provide access to the EGC bus.

### Product families documented by OASE as OASE Control compatible

#### Filter pumps

- AquaMax Eco Premium (CORE 6)
- AquaMax Eco Expert
- AquaMax Eco Titanium

#### Fountain pumps

- Aquarius Eco Premium
- Aquarius Eco Expert

#### Fountain systems

- PondJet Eco Premium

#### Filters

- ProfiClear Premium Compact OC
- ProfiClear Premium DF-L OC
- ProfiClear Premium DF-XL OC
- ProfiClear Premium Fleece

#### Lighting

- ProfiLux Garden LED Controller

### Verification levels

| Level | Meaning |
| --- | --- |
| Confirmed | Verified by packet capture, live RDM interrogation, or hardware operation |
| Documented | Listed by OASE or represented in OASE application definitions |
| Reported | Reported by a user but not independently verified |
| Unknown | Compatibility or field meaning has not been determined |

### Current tested device

**AquaMax Eco Premium 5000, article 75923**

This pump is actively tested and partially reverse engineered. Confirmed
functions include device discovery, on/off control, power setting, RPM, power
consumption, and the advertised temperature sensors. Additional parameters
remain under investigation, so the device should not yet be described as
fully reverse engineered.

## 3. RDM device database

The tested AquaMax identifies itself with:

- Manufacturer identifier
- Device identifier
- Combined stable RDM UID
- Article number
- Subdevice count

The exact values are installation-specific and are reported by the command-line
utility and Indigo plugin rather than hard-coded here.

RDM `DEVICE_INFO` (`0x0060`) supplies general device information including the
sensor count. Each sensor is described with `SENSOR_DEFINITION` (`0x0200`)
before its value is read. This allows sensor numbers and descriptions to be
discovered rather than assuming that every EGC product has the AquaMax layout.

`SUPPORTED_PARAMETERS` (`0x0050`) is a promising device-capability query
defined by RDM and represented in the OASE application. Its reply has not yet
been decoded from the tested pump.

## 4. Known PIDs and sensors

### Confirmed or implemented parameters

| PID | Name | Access used by this project | Notes |
| --- | --- | --- | --- |
| `0x0060` | `DEVICE_INFO` | Read | Includes the advertised sensor count |
| `0x0200` | `SENSOR_DEFINITION` | Read | One-byte sensor selector |
| `0x0201` | `SENSOR_VALUE` | Read | One-byte sensor selector |
| `0x1010` | EGC on/off | Read/write | `0x00` off, nonzero on |
| `0x8039` | Pump control speed | Read/write | Byte value scaled between 0 and 100 percent |

### AquaMax Eco Premium 5000 sensor selectors

| Sensor | Observed description | Interpretation | Status |
| --- | --- | --- | --- |
| `1` | `ActualSpeed` | Current pump speed in RPM | Confirmed |
| `3` | `Temp Modul` | Module temperature; appears fixed at 25 °C on the tested pump | Confirmed value, physical meaning uncertain |
| `4` | `Temp_PCB` | Pump electronics temperature | Confirmed |
| `5` | `Temp Water` | Water temperature | Confirmed |
| `9` | `SFCFunction` | Current SFC stage | Definition confirmed; value mapping derived from OASE application |
| `10` | `POWER` | Current electrical power consumption in watts | Confirmed |

Other advertised sensors include nominal speed, voltage, current, and
reed-contact information. They are retained as research leads and are not all
currently exposed by the tools.

### Seasonal Flow Control

Seasonal Flow Control (SFC) automatically reduces water volume and head as
water temperature falls. Current OASE product documentation says that the
reduction can reach 50 percent. OASE also describes transitions at
approximately 17 °C and 10 °C, although those precise thresholds have not been
confirmed for article 75923.

OASE application definitions distinguish two values:

- PID `0x8038`: SFC enabled/disabled
- `SENSOR_VALUE` selector `9`: current automatic SFC stage

The application maps the stage bytes as follows:

| Raw value | Stage |
| --- | --- |
| `0` | Maximum |
| `1` | Medium |
| `2` | Minimum |

The stage is read-only in the OASE application: the pump selects it
automatically. The tools therefore report both SFC enabled and SFC mode as
read-only status. They do not provide an SFC control action.

Live hardware validation of the two returned values is still required. The
first Indigo debug capture confirmed that the pump advertises sensor 9 as
`SFCFunction`, but it did not contain the OASE application's separate,
encrypted write transaction.

### Locally available data and cloud statistics

The OASE application marks RPM and power consumption as cloud-relevant and
samples them for cloud use every 15 seconds. Those same values are ordinary
local RDM sensor readings. Error state, status information, operating hours,
PWM, firmware, and supported-parameter definitions are also represented as
local RDM data in the application libraries.

This supports the working hypothesis that OASE cloud Statistics stores,
aggregates, graphs, and remotely exposes measurements originating locally.
It does not prove that every historical or derived cloud value is available
from the controller. Indigo can independently retain and graph locally polled
measurements without enabling OASE cloud service.

## 5. Packet formats

Detailed ONet framing, discovery, callback TLS, live-scene socket control, EGC
discovery, and RDM wrapper notes are maintained in
[`oase_fm_master_protocol_notes_updated.txt`](oase_fm_master_protocol_notes_updated.txt).

At a high level:

1. The client sends UDP discovery to the FM-Master.
2. The client requests a TCP callback.
3. The FM-Master connects to the client's TLS listener.
4. The client authenticates with the OASE app password.
5. ONet requests and replies are exchanged inside TLS.
6. EGC operations carry standard-style RDM messages inside ONet wrappers.

## 6. Reverse-engineering notes

Evidence is labelled according to its source:

- **Live confirmed**: observed against the tested FM-Master and pump
- **Application-derived**: recovered from OASE application definitions or
  converters
- **Inferred**: consistent with observed data but not yet independently tested

Application-derived definitions are useful research leads, not automatic proof
that a particular device implements a field. Optional reads must fail safely
so that unsupported values do not prevent normal socket or EGC operation.

Mocked unit tests validate parsing, mapping, and failure handling. They do not
replace hardware validation against an FM-Master, an attached EGC device, and
the Indigo runtime.

## 7. Indigo plugin architecture

The Indigo plugin represents four physical or logical devices:

| Indigo device | Representation |
| --- | --- |
| Switched socket | Physical FM-Master sockets 1, 2, or 4 |
| Dimmable socket | Physical FM-Master socket 3 |
| EGC device | One automatically discovered downstream EGC device |
| FM-Master controller | Controller connectivity, discovery metadata, and Wi-Fi RSSI |

One complete poll updates every configured Indigo device. The EGC device
reports control state, RPM, watts, available temperatures, identity fields,
and read-only SFC status. Indigo automation is responsible for warnings,
seasonal pump control, histories, and graphs; those policies are not embedded
in the protocol plugin.

## 8. Command-line utility

The established status command reads FM-Master, controller, and EGC state:

```bash
python3 oase_control.py \
  --device-ip 192.168.5.176 \
  --local-ip 192.168.5.10 \
  status
```

State changes remain in the normal `set` command and may be comma-separated:

```bash
python3 oase_control.py \
  --device-ip 192.168.5.176 \
  --local-ip 192.168.5.10 \
  set 4 on, 3 off, dimmer 128, egc on, power 50
```

Raw EGC discovery and RDM commands are available for protocol investigation.
The SFC fields added to normal status are read-only.

## 9. Contributing

Useful contributions include:

- Packet captures with the exact action and timestamp documented
- Sensor definitions and values from additional OASE Control devices
- Manufacturer, article, firmware, and model identifiers
- Reproducible hardware observations
- Tests for newly decoded packet fields

Do not include controller passwords, account tokens, private certificates,
serial numbers from installations that should remain private, or cloud-service
bypass instructions.

When adding a field, document whether it is live confirmed,
application-derived, or inferred. Keep controller transport, EGC device data,
Indigo presentation, and automation policy separate.

## References

- [OASE AquaMax Eco Premium family](https://www.oase.com/fr-fr/index-des-produits/family/f/aquamax-eco-premium.1001505098.html)
- [OASE pond energy-saving and SFC overview](https://www.oase.com/fr-fr/mode-de-vie/concevoir-des-espaces-de-vie-economes-en-energie/economiser-l-electricite-dans-un-etang.html)
- [ANSI E1.20 RDM overview](https://tsp.esta.org/tsp/documents/published_docs.php)
- [mr-suw/ioBroker.oasecontrol](https://github.com/mr-suw/ioBroker.oasecontrol)
