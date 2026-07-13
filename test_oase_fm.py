import subprocess
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import oase_fm


ROOT = Path(__file__).resolve().parent


class ProtocolTests(unittest.TestCase):
    def test_password_is_redacted_from_protocol_debug_log(self):
        server = oase_fm.TlsCallbackServer("127.0.0.1", 0)
        server._tls_socket = Mock()
        server._read_packet = Mock(return_value=b"reply")
        password_payload = b"diagnostic-secret"
        packet = oase_fm.Protocol().make_packet(
            oase_fm.PASSWORD_CHECK, password_payload
        )

        with self.assertLogs("oase", level="DEBUG") as captured:
            reply = server.request(packet)

        log_output = "\n".join(captured.output)
        self.assertEqual(reply, b"reply")
        self.assertIn("PASSWORD_CHECK payload=<redacted>", log_output)
        self.assertNotIn(password_payload.hex().upper(), log_output)

    def test_failed_connect_releases_callback_listener(self):
        controller = oase_fm.OaseController("192.0.2.1", "192.0.2.2", "pw")
        listener = Mock()
        listener.start.side_effect = TimeoutError("timed out")

        with patch.object(oase_fm, "TlsCallbackServer", return_value=listener):
            with self.assertRaises(TimeoutError):
                controller.connect()

        listener.close.assert_called_once_with()
        self.assertIsNone(controller._tls)

    def test_packet_round_trip(self):
        protocol = oase_fm.Protocol()
        packet = protocol.make_packet(oase_fm.GET_LIVE_SCENE, b"payload")

        parsed = protocol.parse_packet(packet)

        self.assertEqual(parsed.packet_type, oase_fm.GET_LIVE_SCENE)
        self.assertEqual(parsed.transaction, 0)
        self.assertEqual(parsed.payload, b"payload")

    def test_set_scene_payload(self):
        self.assertEqual(
            oase_fm.make_set_scene_payload(4, 128),
            bytes.fromhex("04000000000000000064020480"),
        )

    def test_egc_state_format(self):
        device = oase_fm.EgcDevice(123, 456, 0x4F41, 1)
        state = oase_fm.EgcState(
            device=device,
            on=True,
            power=50,
            rpm=2345,
            watts=78,
        )

        self.assertEqual(
            oase_fm._format_egc_state(state),
            "egc=on\npower=50\nrpm=2345\nwatts=78\nuid=4F41:000001C8",
        )

    def test_rdm_sensor_definition_and_value_parsing(self):
        definition_data = (
            bytes(
                (
                    3,
                    oase_fm.RDM_SENSOR_TYPE_POWER,
                    oase_fm.RDM_SENSOR_UNIT_WATTS,
                    0,
                )
            )
            + struct.pack(">hhhhB", 0, 500, 0, 500, 0)
            + b"Power consumption"
        )
        definition = oase_fm.parse_rdm_sensor_definition(definition_data)
        value = oase_fm.parse_rdm_sensor_value(
            bytes((3,)) + struct.pack(">hhhh", 78, 12, 95, 78)
        )

        self.assertEqual(definition.sensor_number, 3)
        self.assertEqual(definition.description, "Power consumption")
        self.assertEqual(value.present, 78)
        self.assertEqual(oase_fm.scale_rdm_sensor_value(definition, value), 78)

    def test_get_egc_state_reads_onoff_and_power(self):
        controller = oase_fm.OaseController("192.0.2.1", "192.0.2.2", "pw")
        device = oase_fm.EgcDevice(123, 456, 0x4F41, 1)
        nominal_speed_definition = (
            bytes((0, 0x0B, 0, 0))
            + struct.pack(">hhhhB", 0, 5000, 0, 5000, 0)
            + b"NominalSpeed"
        )
        rpm_definition = (
            bytes((1, 0x0B, 0, 0))
            + struct.pack(">hhhhB", 0, 5000, 0, 5000, 0)
            + b"ActualSpeed"
        )
        watts_definition = (
            bytes(
                (
                    2,
                    oase_fm.RDM_SENSOR_TYPE_POWER,
                    oase_fm.RDM_SENSOR_UNIT_WATTS,
                    0,
                )
            )
            + struct.pack(">hhhhB", 0, 500, 0, 500, 0)
            + b"Power"
        )
        device_info = bytearray(19)
        device_info[18] = 3

        def rdm_get(_uid, parameter_id, parameter_data=b""):
            if parameter_id == 0x1010:
                return Mock(parameter_data=b"\xff")
            if parameter_id == 0x8039:
                return Mock(parameter_data=bytes((128,)))
            if parameter_id == oase_fm.RDM_DEVICE_INFO:
                return Mock(parameter_data=bytes(device_info))
            if parameter_id == oase_fm.RDM_SENSOR_DEFINITION:
                definitions = {
                    b"\x00": nominal_speed_definition,
                    b"\x01": rpm_definition,
                    b"\x02": watts_definition,
                }
                return Mock(parameter_data=definitions[parameter_data])
            if parameter_id == oase_fm.RDM_SENSOR_VALUE:
                present = 2345 if parameter_data == b"\x01" else 78
                return Mock(
                    parameter_data=parameter_data
                    + struct.pack(">hhhh", present, present, present, present)
                )
            raise AssertionError(f"unexpected RDM PID 0x{parameter_id:04X}")

        controller.rdm_get = Mock(side_effect=rdm_get)

        state = controller.get_egc_state(device)

        self.assertTrue(state.on)
        self.assertEqual(state.power, 51)
        self.assertEqual(state.rpm, 2345)
        self.assertEqual(state.watts, 78)

    def test_missing_telemetry_does_not_break_egc_state(self):
        controller = oase_fm.OaseController("192.0.2.1", "192.0.2.2", "pw")
        device = oase_fm.EgcDevice(123, 456, 0x4F41, 1)
        controller.rdm_get = Mock(
            side_effect=[
                Mock(parameter_data=b"\xff"),
                Mock(parameter_data=bytes((128,))),
                oase_fm.OaseError("DEVICE_INFO is unsupported"),
            ]
        )

        state = controller.get_egc_state(device)

        self.assertIsNone(state.rpm)
        self.assertIsNone(state.watts)


class CliContractTests(unittest.TestCase):
    def test_established_status_command_parses_unchanged(self):
        args = oase_fm.build_parser().parse_args(
            [
                "--device-ip",
                "192.168.5.176",
                "--local-ip",
                "192.168.5.10",
                "status",
            ]
        )

        self.assertEqual(args.device_ip, "192.168.5.176")
        self.assertEqual(args.local_ip, "192.168.5.10")
        self.assertEqual(args.command, "status")

    def test_comma_separated_set_operations(self):
        self.assertEqual(
            oase_fm.parse_set_operations(
                ["4", "on,", "3", "off,", "dimmer", "128"]
            ),
            [
                ("outlet", 4, 0xFF),
                ("outlet", 3, 0x00),
                ("dimmer", 4, 128),
            ],
        )

    def test_both_entry_points_expose_same_cli(self):
        for script in ("oase_control.py", "oase_control_rdm.py"):
            result = subprocess.run(
                [sys.executable, str(ROOT / script), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("{status,set,egc,rdm}", result.stdout)


if __name__ == "__main__":
    unittest.main()
