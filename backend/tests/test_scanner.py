import io
import os
import pickle
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from backend.scanner import digest, report, validate_content


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='modelshield-scanner-')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'artifact'

    def test_pickle_global_is_reported_without_execution(self):
        marker = Path(self.directory.name) / 'would-have-executed'

        class Dangerous:
            def __reduce__(self):
                return os.system, ('echo marker > ' + str(marker),)

        self.path.write_bytes(pickle.dumps(Dangerous()))
        validate_content(self.path, '.pkl', 'application/octet-stream')
        findings, evidence, observed = report(self.path, '.pkl', digest(self.path))
        self.assertFalse(marker.exists())
        self.assertEqual(observed, digest(self.path))
        self.assertTrue(any(item['severity'] == 'HIGH' for item in findings))
        self.assertTrue(evidence)

    def test_archive_traversal_is_reported_without_extraction(self):
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr('../escape', 'test')
            archive.writestr('payload.pkl', pickle.dumps({'x': 1}))
        validate_content(self.path, '.zip', 'application/zip')
        findings, _, _ = report(self.path, '.zip', digest(self.path))
        self.assertTrue(any(item['title'] == 'Archive traversal paths' for item in findings))
        self.assertTrue(any(item['title'] == 'Embedded pickle payload' for item in findings))
        self.assertFalse((Path(self.directory.name).parent / 'escape').exists())

    def test_bad_file_signatures_and_media_type_are_rejected(self):
        self.path.write_bytes(b'not a model')
        for extension in ('.zip', '.h5', '.safetensors', '.tar', '.gz', '.onnx'):
            with self.subTest(extension=extension):
                with self.assertRaises(ValueError):
                    validate_content(self.path, extension, 'application/octet-stream')
        with self.assertRaises(ValueError):
            validate_content(self.path, '.pkl', 'text/html')

    def test_structural_safetensors_header_is_accepted_with_limited_coverage(self):
        header = b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
        self.path.write_bytes(struct.pack('<Q', len(header)) + header + b'\x00' * 4)
        validate_content(self.path, '.safetensors', 'application/octet-stream')
        findings, _, _ = report(self.path, '.safetensors', digest(self.path))
        self.assertEqual([item['severity'] for item in findings], ['INFO'])


if __name__ == '__main__':
    unittest.main()
