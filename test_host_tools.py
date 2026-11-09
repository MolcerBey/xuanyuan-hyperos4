import base64
import hashlib
import unittest
import urllib.error
from unittest import mock

from prepare_host_tools import REPOSITORY, download


class HostToolDownloadTests(unittest.TestCase):
    def setUp(self):
        self.data = b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00'
        self.item = {'path': 'linux-x86/bin/lpmake', 'size': len(self.data),
                     'sha256': hashlib.sha256(self.data).hexdigest()}
        self.commit = 'a' * 40
        self.url = f'{REPOSITORY}/+/{self.commit}/{self.item["path"]}?format=TEXT'

    def response(self):
        result = mock.MagicMock()
        result.__enter__.return_value = result
        result.geturl.return_value = self.url
        result.headers = {}
        result.read.side_effect = [base64.b64encode(self.data), b'']
        return result

    def test_transient_503_is_retried_without_relaxing_hash_checks(self):
        error = urllib.error.HTTPError(self.url, 503, 'unavailable', {}, None)
        with mock.patch('prepare_host_tools.urllib.request.urlopen',
                        side_effect=[error, self.response()]) as request, \
                mock.patch('prepare_host_tools.time.sleep') as sleep:
            data, url = download(self.item, self.commit)
        self.assertEqual(data, self.data)
        self.assertEqual(url, self.url)
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_permanent_http_error_is_not_retried(self):
        error = urllib.error.HTTPError(self.url, 404, 'missing', {}, None)
        with mock.patch('prepare_host_tools.urllib.request.urlopen', side_effect=error) as request, \
                mock.patch('prepare_host_tools.time.sleep') as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                download(self.item, self.commit)
        request.assert_called_once()
        sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
