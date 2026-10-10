"""Hash-pinned upstream MiSub parser/converter; never changes a deployed MiSub."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen

COMMIT = 'f8362c55ef9886289debf6263822b13636739008'
FILES = {
    'functions/utils/url-to-clash.js': '6cf69fa3b21809a169c9beeb3cfc9dcd534d885d1839a617ddb2e8744dddd97d',
    'functions/utils/node-utils.js': '1ff82dff9adf43bd680f8e83bc32a658ef14d279b0e992431c31f2e8df420c1f',
    'functions/modules/utils/metadata-extractor.js': '244cfa0e4050bbc3c1d60806487a7a1ffac418285582495be66b4ff56f75e935',
    'functions/modules/utils/geo-utils.js': '9c37c8903307fd4a06beab041b21382ad6f71b3bd6a915925ae4be3d998a65a8',
    'src/utils/protocols/converters/tuic.js': '03c040c90892ab98d78bcf61d029ea5c39e5ef7bbc7c2936f83cb4e099fc76ed',
}


def roundtrip(link):
    node = os.environ.get('NODE_BINARY') or shutil.which('node')
    if not node:
        raise RuntimeError('Node.js required for actual MiSub converter')
    with tempfile.TemporaryDirectory(prefix='relay-misub-test-') as folder:
        root = Path(folder)
        (root / 'package.json').write_text('{"type":"module"}')
        for name, digest in FILES.items():
            with urlopen('https://raw.githubusercontent.com/imzyb/MiSub/' + COMMIT + '/' + name, timeout=45) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError('MiSub fixture hash mismatch')
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        runner = root / 'run.mjs'
        runner.write_text("import {urlToClashProxy} from './functions/utils/url-to-clash.js';\n"
            "import {convertTuicToUrl} from './src/utils/protocols/converters/tuic.js';\n"
            "let input='';for await(const chunk of process.stdin) input+=chunk;\n"
            "const parsed=urlToClashProxy(input.trim());const link=convertTuicToUrl(parsed);\n"
            "process.stdout.write(JSON.stringify({parsed,link,reparsed:urlToClashProxy(link)}));\n")
        result = subprocess.run([node, str(runner)], input=link.encode(), capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError('MiSub converter failed: ' + result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)
