"""Release selection, integrity, safe extraction and update cancellation."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import updates as u


def published(tag='v1.4.0', data=b'archive'):
    name = 'socks5-relay-manager-' + tag + '-install.tar.gz'
    return dict(tag_name=tag, draft=False, prerelease=False, assets=[dict(
        name=name, digest='sha256:' + hashlib.sha256(data).hexdigest(), size=len(data),
        browser_download_url='https://github.com/' + u.REPO + '/releases/download/' + tag + '/' + name)])


def archive(files, link=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as target:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            if link:
                item.type, item.linkname, item.size = tarfile.SYMTYPE, '/etc/passwd', 0
            target.addfile(item, io.BytesIO(data))
    return stream.getvalue()


class Updates(unittest.TestCase):
    def test_excludes_prerelease_draft_bad_digest_and_foreign_download(self):
        self.assertEqual(u.release(published())['tag'], 'v1.4.0')
        for field, value in [('draft', True), ('prerelease', True), ('tag_name', 'v1.4.0;id'), ('tag_name', 'v1.5.0-rc1')]:
            item = published()
            item[field] = value
            self.assertIsNone(u.release(item))
        for field, value in [('digest', ''), ('digest', 'md5:' + 'a' * 32), ('size', 0),
                             ('browser_download_url', 'https://evil.example/install.tar.gz')]:
            item = published()
            item['assets'][0][field] = value
            self.assertIsNone(u.release(item))

    def test_versions_sorted_numerically_not_lexicographically(self):
        with patch.object(u, 'metadata', return_value=[published('v1.9.0'), published('v1.10.0'), published('v1.3.3')]):
            self.assertEqual([r['tag'] for r in u.releases()], ['v1.10.0', 'v1.9.0', 'v1.3.3'])

    def test_latest_is_queried_from_official_latest_endpoint(self):
        with patch.object(u, 'metadata', return_value=published()) as fetch:
            self.assertEqual(u.latest()['tag'], 'v1.4.0')
        fetch.assert_called_once_with('/releases/latest')

    def test_download_hash_failure_never_runs_installer_or_writes_valid_cache(self):
        item = u.release(published(data=b'good'))
        with tempfile.TemporaryDirectory() as directory, patch.object(u, 'open_url', return_value=io.BytesIO(b'evil')), patch.object(u.subprocess, 'run') as run:
            with self.assertRaises(u.UpdateError):
                u.download(item, directory)
            self.assertFalse((Path(directory) / item['sha256']).exists())
            self.assertFalse(list(Path(directory).glob('.update-*')))
            run.assert_not_called()

    def test_download_retries_and_reuses_only_valid_cache(self):
        item = u.release(published(data=b'good'))
        with tempfile.TemporaryDirectory() as directory, patch.object(u, 'open_url', side_effect=[OSError('offline'), io.BytesIO(b'good')]) as fetch, patch.object(u.time, 'sleep'):
            path = u.download(item, directory)
            self.assertEqual(path.read_bytes(), b'good')
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(u.download(item, directory), path)
            self.assertEqual(fetch.call_count, 2)
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_partial_response_is_retried_without_trusting_partial_cache(self):
        item = u.release(published(data=b'good'))
        with tempfile.TemporaryDirectory() as directory, patch.object(u, 'open_url', side_effect=[io.BytesIO(b'go'), io.BytesIO(b'good')]) as fetch, patch.object(u.time, 'sleep'):
            self.assertEqual(u.download(item, directory).read_bytes(), b'good')
            self.assertEqual(fetch.call_count, 2)

    def test_archive_rejects_traversal_links_and_version_mismatch(self):
        for files, link in [({'../escape': b'x'}, False), ({'/escape': b'x'}, False),
                            ({'C:/escape': b'x'}, False), ({'scripts/manager.py': b'x'}, True),
                            ({'VERSION': b'9.0.0'}, False)]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'input.tar.gz'
                path.write_bytes(archive(files, link))
                folder = Path(directory) / 'output'
                folder.mkdir()
                with self.assertRaises(u.UpdateError):
                    u.unpack(path, folder, 'v1.4.0')
                self.assertFalse((Path(directory) / 'escape').exists())

    def test_safe_archive_version_and_executable(self):
        files = {'VERSION': b'1.4.0', 'install.sh': b'#!/bin/bash\n', 'scripts/manager.py': b'',
                 'socks-menu.sh': b'', 'uninstall.sh': b'', 'systemd/socks-relay@.service': b''}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.tar.gz'
            path.write_bytes(archive(files))
            folder = Path(directory) / 'output'
            folder.mkdir()
            u.unpack(path, folder, 'v1.4.0')
            self.assertEqual((folder / 'VERSION').read_text(), '1.4.0')
            if os.name == 'posix':
                self.assertEqual((folder / 'install.sh').stat().st_mode & 0o777, 0o700)

    def test_cancel_and_already_latest_do_not_backup_or_install(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            (app / 'current').mkdir()
            (app / 'current/VERSION').write_text('1.4.0')
            manager = Mock()
            with patch.object(u, 'latest', return_value=u.release(published())), patch.object(u, 'install') as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(u.menu(manager, app, Mock(return_value='1'), Mock()))
                install.assert_not_called()
                manager.backup.assert_not_called()
            with patch.object(u, 'releases', return_value=[u.release(published('v1.3.3'))]), patch.object(u, 'install') as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(u.menu(manager, app, Mock(side_effect=['2', '1']), Mock(return_value=False)))
                install.assert_not_called()

    def test_history_selection_needs_no_version_input(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory)
            (app / 'current').mkdir()
            (app / 'current/VERSION').write_text('1.4.0')
            selected = u.release(published('v1.3.3'))
            with patch.object(u, 'releases', return_value=[selected]), patch.object(u, 'install') as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(u.menu(Mock(), app, Mock(side_effect=['2', '1']), Mock(return_value=True)))
                self.assertEqual(install.call_args.args[1], selected)

    def test_incompatible_downgrade_does_not_backup_or_run_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = Mock()
            with patch.object(u, 'download', return_value=Path(directory) / 'input'), patch.object(u, 'unpack'), patch.object(u.subprocess, 'run', return_value=Mock(returncode=1)) as run:
                with self.assertRaises(u.UpdateError):
                    u.install(manager, u.release(published('v1.3.3')), directory)
            self.assertEqual(run.call_count, 1)
            manager.backup.assert_not_called()

    def test_installer_uses_resolved_interpreter_parent_and_local_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = Mock()
            manager.lock.return_value = contextlib.nullcontext()
            with patch.object(u, 'download', return_value=Path(directory) / 'input'), patch.object(u, 'unpack'), patch.object(u.subprocess, 'run', return_value=Mock(returncode=0)) as run:
                u.install(manager, u.release(published('v1.3.3')), directory)
            manager.backup.assert_called_once()
            self.assertEqual(run.call_count, 2)
            call = run.call_args
            self.assertEqual(call.args[0][-1], '--local')
            self.assertEqual(call.kwargs['env']['PATH'].split(os.pathsep)[0], str(Path(sys.executable).resolve().parent))


if __name__ == '__main__':
    unittest.main(verbosity=2)
