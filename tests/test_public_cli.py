import subprocess
import sys
import unittest
from pathlib import Path


class PublicNamingTests(unittest.TestCase):
    def test_entry_point_and_command_list(self):
        root = Path(__file__).resolve().parents[1]
        entry = root / 'bin' / 'cannc'
        self.assertTrue(entry.is_file())
        self.assertFalse((root / 'bin' / 'canncc').exists())
        proc = subprocess.run([sys.executable, str(entry), '--help'], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('usage: cannc ', proc.stdout)
        for command in ('bootstrap', 'mount', 'unmount', 'doctor', 'version', 'recover', 'compile', 'link', 'build'):
            self.assertIn(command, proc.stdout)

    def test_recover_requires_manifest(self):
        entry = Path(__file__).resolve().parents[1] / 'bin' / 'cannc'
        proc = subprocess.run([sys.executable, str(entry), 'recover'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn('manifest', proc.stderr)
        self.assertIn('cannc recover', proc.stderr)


if __name__ == '__main__':
    unittest.main()
