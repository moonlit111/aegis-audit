import io
import json
from pathlib import Path
import stat
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from prepare_small_demos import CATALOG, measure_archive


def archive(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as output:
        for name, content in entries:
            if isinstance(name, str):
                info = zipfile.ZipInfo()
                info.filename = name
                name = info
            output.writestr(name, content)
    return buffer.getvalue()


class SmallDemoTests(unittest.TestCase):
    def test_counts_full_source_files_once_and_keeps_comments_in_physical_metric(self):
        result = measure_archive(archive([
            ('sample-rev/main.py', '# comment\n\ndef main():\n    return 1\n'),
            ('sample-rev/lib/util.c', 'int value(void) { return 1; }\n'),
            ('sample-rev/README.md', 'description\n'),
        ]), 'sample-rev')
        self.assertEqual(result['archive_files'], 3)
        self.assertEqual(result['source_files'], 2)
        self.assertEqual(result['source_lines'], 5)
        self.assertEqual(result['source_nonblank_lines'], 4)
        self.assertEqual([item['path'] for item in result['files']], ['lib/util.c', 'main.py'])
        self.assertTrue(all(len(item['sha256']) == 64 for item in result['files']))

    def test_rejects_unsafe_entries_and_wrong_revisions_without_extracting(self):
        for path in ['sample-rev/../main.py', '/sample-rev/main.py',
                     'wrong-rev/main.py', 'sample-rev\\main.py']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                measure_archive(archive([(path, 'pass\n')]), 'sample-rev')
        link = zipfile.ZipInfo('sample-rev/main.py')
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            measure_archive(archive([(link, 'outside.py')]), 'sample-rev')

    def test_catalog_is_small_pinned_and_not_formal_acceptance(self):
        candidates = json.loads(CATALOG.read_text(encoding='utf-8'))
        self.assertEqual(len(candidates), 2)
        for candidate in candidates:
            self.assertRegex(candidate['revision'], r'^[a-f0-9]{40}$')
            self.assertLessEqual(candidate['max_source_lines'], 2500)
            self.assertFalse(candidate['formal_acceptance'])


if __name__ == '__main__':
    unittest.main()
