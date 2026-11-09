import hashlib
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from assemble_candidate import prepare_radio


class AssemblyRadioTests(unittest.TestCase):
    def test_durable_hash_bound_cache_is_the_only_download_source(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = pathlib.Path.cwd()
            root = pathlib.Path(directory)
            try:
                os.chdir(root)
                source_root = root / 'out/rom-radio/images'
                source_root.mkdir(parents=True)
                (root / 'work/images').mkdir(parents=True)
                files = []
                for partition in ('modem', 'modemfirmware'):
                    data = ('verified ' + partition).encode()
                    path = source_root / (partition + '.img')
                    path.write_bytes(data)
                    files.append({'partition': partition, 'size': len(data),
                                  'sha256': hashlib.sha256(data).hexdigest()})
                cache = {'schema': 1, 'asset_id': 123, 'size': 456,
                         'sha256': 'ab' * 32}
                report = {'phone_accessed': False, 'installers_executed': False,
                          'files': files}
                with mock.patch('assemble_candidate.read_json', side_effect=[cache, report]), \
                        mock.patch('assemble_candidate.download_asset') as fetch, \
                        mock.patch('assemble_candidate.run_script') as run:
                    result = prepare_radio()
                self.assertEqual(result, report)
                fetch.assert_called_once()
                self.assertEqual(fetch.call_args.args[:3], (123, 456, 'ab' * 32))
                run.assert_called_once_with('integrate_radio.py', '--artifact',
                                            pathlib.Path('work/eu-radio-reference.zip'))
                self.assertFalse((root / 'work/eu-radio-reference.zip').exists())
                for record in files:
                    self.assertEqual((root / 'work/images' / (record['partition'] + '.img')).stat().st_size,
                                     record['size'])
            finally:
                os.chdir(previous)


if __name__ == '__main__':
    unittest.main()
