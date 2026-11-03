"""Independent native-library reference, using public synthetic passwords."""
import runpy
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'vendor'))
from argon2.low_level import hash_secret_raw, Type
adapter = runpy.run_path(str(ROOT / 'web/src/argon_adapter.py'))['hash_secret_raw']


class ArgonCompatibility(unittest.TestCase):
    def test_all_variants_and_lanes_match_native(self):
        for kind in Type:
            for lanes in (1, 2, 4, 16):
                with self.subTest(variant=kind.name, lanes=lanes):
                    args = (b'synthetic-test-password', b'synthetic-test-salt', 2, 1024, lanes, 80, kind)
                    self.assertEqual(adapter(*args), hash_secret_raw(*args))

    def test_excessive_work_is_refused(self):
        with self.assertRaises(ValueError):
            adapter(b'test', b'synthetic-test-salt', 32, 262144, 2, 80, Type.ID)


if __name__ == '__main__':
    unittest.main()
