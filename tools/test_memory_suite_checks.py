"""Negative tests: the gate itself must reject stale and over-budget evidence."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_memory_suite as gate
from check_fap_memory import violations


class GateTests(unittest.TestCase):
    def test_source_changes_additions_and_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for folder in ('src', 'config', 'assets'):
                (root / folder).mkdir()
            (root / 'application.fam').write_text('manifest')
            code = root / 'src/app.c'
            code.write_text('original')
            snapshot = {p.relative_to(root).as_posix(): gate.sha(p)
                        for p in root.rglob('*') if p.is_file()}
            gate.source_matches(snapshot, root)
            code.write_text('modified')
            with self.assertRaises(ValueError):
                gate.source_matches(snapshot, root)
            code.write_text('original')
            added = root / 'src/new.c'
            added.write_text('new')
            with self.assertRaises(ValueError):
                gate.source_matches(snapshot, root)
            added.unlink()
            code.unlink()
            with self.assertRaises(ValueError):
                gate.source_matches(snapshot, root)

    def test_reports_and_debug_binary_must_match(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(gate, 'source_matches'):
            root = Path(tmp)
            fap = root / 'tb2_probe.fap'
            elf = root / 'tb2_probe_d.elf'
            fap.write_bytes(b'fap')
            elf.write_bytes(b'elf')
            documents = {
                'source-snapshot.json': {},
                'memory.json': {'sha256': gate.sha(fap)},
                'loader.json': {'sha256': gate.sha(fap)},
                'status-stack.json': {'fap_sha256': gate.sha(fap), 'passed': True,
                                      'elf_sha256': {'tb2_probe': gate.sha(elf)}},
            }
            for name, data in documents.items():
                (root / name).write_text(json.dumps(data))
            gate.validate_evidence(root, fap, root)
            (root / 'loader.json').write_text('{"sha256":"wrong"}')
            with self.assertRaises(ValueError):
                gate.validate_evidence(root, fap, root)
            (root / 'loader.json').write_text(json.dumps(documents['loader.json']))
            elf.write_bytes(b'other build')
            with self.assertRaises(ValueError):
                gate.validate_evidence(root, fap, root)

    def test_payload_preload_section_and_symbol_limits(self):
        policy = gate.read_json(gate.ROOT / 'config/fap_memory.json')
        report = {'resident_payload': 0, 'preload_payload': 0, 'largest_section': 0,
                  'browser_payload': 0, 'backend': {'largest_section': 0},
                  'frontend': {'resident_payload': 0}, 'modules': {'store': {}}}
        self.assertFalse(violations(report, policy))
        cases = [([], 'resident_payload', 'resident_payload_max'),
                 ([], 'browser_payload', 'browser_payload_max'),
                 (['backend'], 'preload_payload', 'backend_preload_max'),
                 (['backend'], 'cached_symbols', 'backend_cached_symbols_max'),
                 (['modules', 'store'], 'preload_payload', 'store_preload_max'),
                 (['modules', 'store'], 'largest_section', 'backend_section_max')]
        for path, field, limit in cases:
            candidate = copy.deepcopy(report)
            node = candidate
            for part in path:
                node = node[part]
            node[field] = policy[limit] + 1
            with self.subTest(limit=limit):
                self.assertTrue(violations(candidate, policy))

    def test_missing_evidence_and_failed_process_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            suite = gate.Suite(Path(tmp))
            self.assertFalse(suite.check('missing', lambda: gate.read_json(Path(tmp) / 'absent.json')))
            self.assertFalse(suite.check('child', lambda: suite.command('child', [sys.executable, '-c', 'raise SystemExit(2)'])))
            self.assertEqual(suite.finish('test'), 1)
            self.assertFalse(gate.read_json(Path(tmp) / 'report.json')['passed'])


if __name__ == '__main__':
    unittest.main()
