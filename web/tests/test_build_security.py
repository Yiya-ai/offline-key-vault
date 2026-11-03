"""Release contamination/advisory regressions. Synthetic files only."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

WEB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEB))
from verify_build import verify
from audit_dependencies import packages, findings


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='key-web-deploy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'dist'
        shutil.copytree(WEB / 'dist', self.root)

    def test_clean(self):
        self.assertTrue(verify(self.root)['ok'])

    def test_nested_private_file(self):
        (self.root / 'licenses' / 'synthetic.key').write_text('synthetic private marker')
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_nested_private_file_even_if_manifest_extended(self):
        data = b'synthetic private marker'
        (self.root / 'licenses' / 'synthetic.key').write_bytes(data)
        manifest = self.root / 'deployment-manifest.json'
        content = json.loads(manifest.read_text())
        content['files']['licenses/synthetic.key'] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        manifest.write_text(json.dumps(content))
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_altered_app(self):
        with (self.root / 'app.js').open('a', encoding='utf-8') as handle:
            handle.write('\n// synthetic contamination')
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_unexpected_directory(self):
        (self.root / 'licenses' / 'extra').mkdir()
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_replaced_wheel_with_rewritten_manifests(self):
        # A self-consistent deployment manifest cannot authorize a new binary.
        assets_file = self.root / 'assets.json'
        assets = json.loads(assets_file.read_text())
        name = next(n for n in assets['files'] if n.startswith('cryptography-'))
        path = self.root / 'assets' / name
        data = path.read_bytes() + b'synthetic-binary-change'
        path.write_bytes(data)
        assets['files'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        assets_file.write_text(json.dumps(assets))
        runtime_file = self.root / 'assets/pyodide-lock.json'
        runtime = json.loads(runtime_file.read_text())
        runtime['packages']['cryptography']['sha256'] = assets['files'][name]['sha256']
        runtime_file.write_text(json.dumps(runtime))
        manifest_file = self.root / 'deployment-manifest.json'
        manifest = json.loads(manifest_file.read_text())
        for file in (path, assets_file, runtime_file):
            content = file.read_bytes()
            manifest['files'][file.relative_to(self.root).as_posix()] = {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}
        manifest_file.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'reviewed dependency lock'):
            verify(self.root)


class AdvisoryTests(unittest.TestCase):
    def test_only_public_packages(self):
        queries = packages()
        self.assertEqual(len(queries), 15)
        self.assertTrue(all(set(q) == {'package', 'version'} for q in queries))
        self.assertEqual(next(q['version'] for q in queries if q['package']['name'] == 'pyasn1'), '0.6.5')

    def test_all_severities_block(self):
        queries = packages()[:1]
        result = findings(queries, {'results': [{'vulns': [{'id': 'SYNTHETIC-1'}]}]})
        self.assertEqual(result[0]['advisories'], ['SYNTHETIC-1'])
        self.assertEqual(findings(queries, {'results': [{}]}), [])

    def test_incomplete_results_fail_closed(self):
        for response in ({}, {'results': []}, {'results': [None]}, {'results': [{'next_page_token': 'more'}]}):
            with self.assertRaises(ValueError):
                findings(packages()[:1], response)


if __name__ == '__main__':
    unittest.main()
