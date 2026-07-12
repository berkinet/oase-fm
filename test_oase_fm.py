import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import oase_fm


ROOT = Path(__file__).resolve().parent


class ProtocolTests(unittest.TestCase):
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
        state = oase_fm.EgcState(device=device, on=True, power=50)

        self.assertEqual(
            oase_fm._format_egc_state(state),
            "egc=on\npower=50\nuid=4F41:000001C8",
        )

    def test_get_egc_state_reads_onoff_and_power(self):
        controller = oase_fm.OaseController("192.0.2.1", "192.0.2.2", "pw")
        device = oase_fm.EgcDevice(123, 456, 0x4F41, 1)
        controller.rdm_get = Mock(
            side_effect=[
                Mock(parameter_data=b"\xff"),
                Mock(parameter_data=bytes((128,))),
            ]
        )

        state = controller.get_egc_state(device)

        self.assertTrue(state.on)
        self.assertEqual(state.power, 51)
        self.assertEqual(
            controller.rdm_get.call_args_list,
            [
                unittest.mock.call(device.uid, 0x1010),
                unittest.mock.call(device.uid, 0x8039),
            ],
        )


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
