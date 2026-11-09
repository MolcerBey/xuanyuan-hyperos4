import pathlib
import tempfile
import unittest
from unittest import mock

from publish_candidate import draft_release, upload_asset


class CandidatePublishTests(unittest.TestCase):
    def test_draft_release_uses_exact_tag_from_release_list(self):
        releases = [{'id': 1, 'draft': False, 'tag_name': 'candidate'},
                    {'id': 2, 'draft': True, 'tag_name': 'other'},
                    {'id': 3, 'draft': True, 'tag_name': 'candidate'}]
        with mock.patch('publish_candidate.gh', return_value=releases) as call:
            release = draft_release('candidate')
        self.assertEqual(release['id'], 3)
        self.assertIn('releases?per_page=100', call.call_args.args[1])

    def test_upload_rechecks_draft_and_remote_asset_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'image.part'
            path.write_bytes(b'candidate')
            release = {'draft': True, 'assets': [{'id': 7, 'name': path.name, 'size': 9,
                       'digest': 'sha256:' + '11' * 32, 'url': 'asset-api',
                       'browser_download_url': 'asset-download'}]}
            with mock.patch('publish_candidate.gh', return_value='uploaded'), \
                    mock.patch('publish_candidate.draft_release', return_value=release):
                result = upload_asset('candidate', path, '11' * 32, 9)
            self.assertEqual(result['asset_id'], 7)
            self.assertTrue(result['remote_sha256_verified'])

    def test_draft_release_retries_until_api_lists_created_draft(self):
        release = {'id': 4, 'draft': True, 'tag_name': 'candidate'}
        with mock.patch('publish_candidate.gh', side_effect=[[], [release]]) as call, \
                mock.patch('publish_candidate.time.sleep') as sleep:
            result = draft_release('candidate')
        self.assertEqual(result['id'], 4)
        self.assertEqual(call.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_upload_waits_for_asset_visibility(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'image.part'
            path.write_bytes(b'candidate')
            release = {'draft': True, 'assets': [{'id': 7, 'name': path.name, 'size': 9,
                       'digest': 'sha256:' + '11' * 32, 'url': 'asset-api',
                       'browser_download_url': 'asset-download'}]}
            with mock.patch('publish_candidate.gh', return_value='uploaded'), \
                    mock.patch('publish_candidate.draft_release',
                               side_effect=[{'draft': True, 'assets': []}, release]), \
                    mock.patch('publish_candidate.time.sleep') as sleep:
                result = upload_asset('candidate', path, '11' * 32, 9)
            self.assertEqual(result['asset_id'], 7)
            sleep.assert_called_once_with(1)

    def test_public_or_ambiguous_release_is_rejected(self):
        with mock.patch('publish_candidate.gh', return_value=[{'draft': False, 'tag_name': 'candidate'}]):
            with self.assertRaisesRegex(ValueError, 'exactly one draft'):
                draft_release('candidate', timeout=0)


if __name__ == '__main__':
    unittest.main()
