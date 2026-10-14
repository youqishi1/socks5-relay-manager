"""Decode actual terminal and PNG QR images, validate TLS, menu and permissions."""
import contextlib
import copy
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, unquote, urlsplit

import cv2
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import access
import manager
import tuic_qr
import test_certificates as fixtures


class QRTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CertificateTests.setUpClass()
        cls.fixture = fixtures.CertificateTests()

    @classmethod
    def tearDownClass(cls):
        fixtures.CertificateTests.tearDownClass()

    def row(self):
        row = self.fixture.row()
        row['access'].update(server_name='tuic.example.test', certificate_trust='system')
        row['access']['tuic_password'] = 'fixture-password:@ /?+%3A#only'
        return row

    def decode(self, image):
        # Ubuntu 22.04's OpenCV is built without QUIRC. Use the independent
        # ZBar reader there rather than skipping actual QR decoding.
        if shutil.which('zbarimg'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'fixture.png'
                ok, encoded = cv2.imencode('.png', image)
                self.assertTrue(ok)
                path.write_bytes(encoded.tobytes())
                result = subprocess.run(['zbarimg', '--quiet', '--raw', str(path)], capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0)
                text = result.stdout.decode('utf-8').rstrip('\r\n')
                self.assertTrue(text)
                return text
        text, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
        self.assertIsNotNone(points)
        self.assertTrue(text)
        return text

    def test_png_and_terminal_decode_to_same_secure_plain_uri(self):
        row = self.row()
        before = copy.deepcopy(row)
        link, code = tuic_qr.build(row, '203.0.113.1')
        png = tuic_qr.png(code)
        image = cv2.imdecode(np.frombuffer(png, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
        self.assertEqual(self.decode(image), link)
        rendered = re.sub(r'\x1b\[[0-9;]*m', '', tuic_qr.terminal(code)).splitlines()
        glyphs = {' ': (255, 255), '▀': (0, 255), '▄': (255, 0), '█': (0, 0)}
        pixels = []
        for line in rendered:
            pairs = [glyphs[glyph] for glyph in line]
            pixels += [[pair[0] for pair in pairs], [pair[1] for pair in pairs]]
        terminal_image = np.repeat(np.repeat(np.array(pixels, dtype=np.uint8), 4, axis=0), 4, axis=1)
        self.assertEqual(self.decode(terminal_image), link)
        parsed = urlsplit(link)
        self.assertEqual(parsed.scheme, 'tuic')
        self.assertEqual(unquote(parsed.username), row['access']['uuid'])
        self.assertEqual(unquote(parsed.password), row['access']['tuic_password'])
        self.assertEqual(parsed.hostname, '203.0.113.1')
        self.assertEqual(parsed.port, 30001)
        self.assertEqual(parse_qs(parsed.query), {'sni': ['tuic.example.test'], 'alpn': ['h3'], 'congestion_control': ['bbr'], 'allow_insecure': ['0']})
        self.assertEqual(parsed.fragment, 'TUIC-20001')
        self.assertNotIn('PRIVATE KEY', link)
        self.assertNotIn('BEGIN CERTIFICATE', link)
        self.assertLessEqual(image.shape[0], 300)
        self.assertTrue(np.all(image[:tuic_qr.BORDER * 4] == 255))
        self.assertTrue(np.all(image[:, :tuic_qr.BORDER * 4] == 255))
        self.assertEqual(row, before)

    def test_self_signed_disabled_and_invalid_endpoint_rejected(self):
        with self.assertRaises(access.AccessError):
            tuic_qr.build(self.fixture.row(), '203.0.113.1')
        row = self.row()
        row['enabled'] = False
        with self.assertRaises(access.AccessError):
            tuic_qr.build(row, '203.0.113.1')
        with self.assertRaises(access.AccessError):
            tuic_qr.build(self.row(), 'https://invalid.example/')

    def test_menu_displays_one_qr_and_saves_private_png_without_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = Mock(root=Path(directory))
            instance.rows.return_value = [self.row()]
            instance.backend.active.return_value = True
            instance.lock.side_effect = contextlib.nullcontext
            answers = iter(['23', '', '0'])
            output = io.StringIO()
            with patch.object(manager, 'public_address', return_value='203.0.113.1'), \
                 patch.object(manager.shutil, 'get_terminal_size', return_value=(100, 60)), \
                 patch.object(manager, 'select_row', side_effect=AssertionError('单节点不应要求选择')), \
                 patch('builtins.input', side_effect=lambda _: next(answers)), contextlib.redirect_stdout(output):
                manager.menu(instance)
            path = instance.root / 'exports' / 'dual' / 'TUIC-20001-二维码.png'
            self.assertTrue(path.is_file())
            self.assertIn('小火箭 → 扫码', output.getvalue())
            self.assertEqual(self.decode(cv2.imdecode(np.frombuffer(path.read_bytes(), dtype=np.uint8), cv2.IMREAD_GRAYSCALE)), tuic_qr.build(self.row(), '203.0.113.1')[0])
            instance.apply.assert_not_called()
            instance.backend.apply.assert_not_called()
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_narrow_terminal_preserves_png_without_wrapping_qr(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = Mock(root=Path(directory))
            instance.rows.return_value = [self.row()]
            output = io.StringIO()
            with patch.object(manager, 'public_address', return_value='203.0.113.1'), \
                 patch.object(manager.shutil, 'get_terminal_size', return_value=(40, 24)), \
                 patch('builtins.input', return_value=''), contextlib.redirect_stdout(output):
                manager.show_tuic_qr(instance)
            self.assertIn('最大化', output.getvalue())
            self.assertNotIn('\x1b[30;107m', output.getvalue())
            path = instance.root / 'exports' / 'dual' / 'TUIC-20001-二维码.png'
            self.assertEqual(self.decode(cv2.imdecode(np.frombuffer(path.read_bytes(), dtype=np.uint8), cv2.IMREAD_GRAYSCALE)), tuic_qr.build(self.row(), '203.0.113.1')[0])

    def test_existing_qr_is_refreshed_when_credentials_and_sni_change(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = Mock(root=Path(directory))
            row = self.row()
            instance.rows.return_value = [row]
            with patch.object(manager, 'public_address', return_value='203.0.113.1'), \
                 patch.object(manager.shutil, 'get_terminal_size', return_value=(40, 24)), \
                 patch('builtins.input', return_value=''), contextlib.redirect_stdout(io.StringIO()):
                manager.show_tuic_qr(instance)
                path = instance.root / 'exports' / 'dual' / 'TUIC-20001-二维码.png'
                old = path.read_bytes()
                row['access']['tuic_password'] = 'replacement-fixture-secret'
                row['access']['server_name'] = 'updated.example.test'
                manager.export_dual(instance)
            self.assertNotEqual(path.read_bytes(), old)
            self.assertEqual(self.decode(cv2.imdecode(np.frombuffer(path.read_bytes(), dtype=np.uint8), cv2.IMREAD_GRAYSCALE)), tuic_qr.build(row, '203.0.113.1')[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
