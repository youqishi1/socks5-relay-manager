"""Reproducible source-only archives and self-contained fixed-release bootstrap."""
import gzip
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

root = Path(__file__).resolve().parents[1]
version = (root / 'VERSION').read_text().strip()
assert re.fullmatch(r'\d+\.\d+\.\d+', version)
files = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z']).decode().split('\0')
blobs = {name: (root / name).read_bytes() for name in files if name and name != 'start.sh'}
assert all(not (root / name).is_symlink() for name in blobs)
folder = root / '.tools'
folder.mkdir(exist_ok=True)
tarpath = folder / ('socks5-relay-manager-v' + version + '-install.tar.gz')
zippath = folder / ('socks5-relay-manager-v' + version + '.zip')
with tarpath.open('wb') as stream:
    with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, data in sorted(blobs.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o755 if name.endswith('.sh') else 0o644, 0
                archive.addfile(info, io.BytesIO(data))
with zipfile.ZipFile(zippath, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for name, data in sorted(blobs.items()):
        info = zipfile.ZipInfo('socks5-relay-manager/' + name, (2026, 10, 22, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, data)
digest = hashlib.sha256(tarpath.read_bytes()).hexdigest()
template = (root / 'scripts/bootstrap.template.sh').read_text()
text = template.replace('@INSTALL_COMMON@', (root / 'scripts/install_common.sh').read_text())
text = text.replace('@VERSION@', version).replace('@SHA256@', digest)
(root / 'start.sh').write_text(text, encoding='utf-8', newline='\n')
for path in (tarpath, zippath):
    print(path.name, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
