import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from audit_candidates import collect, exit_code, save, start_candidate, state, summarize, verify_snapshot


class CandidateAuditTests(unittest.TestCase):
    def test_pinned_source_identity_and_hash_are_required(self):
        candidate = {'id': 'source-01', 'revision': 'a' * 40}
        evidence = {'candidate': candidate, 'snapshot_id': 'snapshot', 'target_sha256': 'b' * 64}
        snapshot = {'id': 'snapshot', 'kind': 'TARGET_KIND_GIT', 'state': 'SNAPSHOT_STATE_READY',
                    'resolvedRevision': 'a' * 40, 'targetSha256': 'b' * 64}
        verify_snapshot(candidate, evidence, snapshot)
        for changes in [{'kind': 'TARGET_KIND_BINARY'}, {'resolvedRevision': 'c' * 40},
                        {'targetSha256': 'c' * 64}, {'state': 'SNAPSHOT_STATE_IMPORTING'},
                        {'id': 'other'}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_snapshot(candidate, evidence, snapshot | changes)

    def test_lost_create_response_reuses_persisted_request_id(self):
        api = Mock(base='http://127.0.0.1:7331')
        api.rpc.side_effect = [OSError('lost response'), {'run': {'id': 'run', 'state': 'RUN_STATE_RUNNING'}}]
        result = {'snapshot_id': 'snapshot'}
        saved = []
        checkpoint = lambda: saved.append(dict(result))
        with self.assertRaises(OSError):
            start_candidate(api, result, {}, checkpoint)
        request_id = saved[0]['request_id']
        self.assertNotIn('run_id', saved[0])
        start_candidate(api, result, {}, checkpoint)
        self.assertEqual(result['run_id'], 'run')
        self.assertEqual([call.kwargs['requestId'] for call in api.rpc.call_args_list],
                         [request_id, request_id])
        start_candidate(api, result, {}, checkpoint)
        self.assertEqual(api.rpc.call_count, 2)

    def test_partial_or_validated_static_results_never_count_as_acceptance(self):
        run = {'state': 'RUN_STATE_PARTIAL', 'unitCount': '4', 'summaryJson': json.dumps({
            'eligible_unit_count': 4, 'model_usage': {'measured_tokens': 70, 'unknown_usage_calls': 1}})}
        task = {'itemKey': 'unit', 'role': 'AUDITOR', 'status': 'SUCCEEDED'}
        result = summarize(run, {'tasks': [task, task], 'findings': [
            {'reviewStatus': 'VALIDATED', 'category': 'AUTHORIZATION'}]})
        self.assertEqual(result['audited_units'], 1)
        self.assertFalse(result['all_eligible_units_audited'])
        self.assertFalse(result['formal_acceptance'])
        self.assertFalse(result['target_executed'])
        self.assertEqual(result['exploitation'], 'NOT_RUN')
        self.assertEqual(result['model_usage']['unknown_usage_calls'], 1)
        self.assertEqual(result['validated_categories'], {'AUTHORIZATION': 1})
        with self.assertRaises(ValueError):
            summarize(run, {'runtime': [{'id': 'unexpected'}]})

    def test_collect_only_writes_partial_evidence_without_requesting_reports(self):
        api = Mock()
        api.rpc.return_value = {}
        result = {'candidate': {'id': 'source-01'}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            collect(api, result, {'id': 'run', 'state': 'RUN_STATE_RUNNING'}, output, lambda: None)
            self.assertTrue((output / 'source-01/audit.json').is_file())
        self.assertEqual(api.rpc.call_count, 1)
        self.assertNotIn('evidence_complete', result)

    def test_completed_reports_preserve_not_run_and_reuse_report_ids(self):
        api = Mock()
        api.rpc.side_effect = [{}, {'report': {'artifactId': 'j'}},
                               {'report': {'artifactId': 'h'}}, {'report': {'artifactId': 'm'}}]
        report = json.dumps({'checks': {'fuzzing': 'NOT_RUN', 'runtime_verification': 'NOT_RUN',
                                        'exploitation': 'NOT_RUN'}}).encode()
        api.download.side_effect = [report, b'<html>NOT_RUN</html>', b'NOT_RUN']
        result = {'candidate': {'id': 'source-01'}}
        run = {'id': 'run', 'state': 'RUN_STATE_COMPLETED'}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            collect(api, result, run, output, lambda: None)
            self.assertTrue(result['evidence_complete'])
            self.assertFalse(result['formal_acceptance'])
            self.assertEqual(len(result['reports']['json']['sha256']), 64)
            api.rpc.reset_mock(side_effect=True)
            api.rpc.return_value = {}
            api.download.side_effect = [report, b'<html>NOT_RUN</html>', b'NOT_RUN']
            collect(api, result, run, output, lambda: None)
            self.assertEqual(api.rpc.call_count, 1)

    def test_atomic_checkpoint_and_wire_states(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.json'
            save(path, {'old': True})
            save(path, {'new': True})
            self.assertEqual(json.loads(path.read_text()), {'new': True})
            self.assertFalse(path.with_suffix('.json.tmp').exists())
        self.assertEqual(state('RUN_STATE_PARTIAL'), 'PARTIAL')
        self.assertEqual(state('RUNNING'), 'RUNNING')

    def test_exporting_partial_results_is_not_a_successful_audit_exit(self):
        result = {'evidence_complete': True, 'state': 'RUN_STATE_PARTIAL',
                  'all_eligible_units_audited': False}
        self.assertEqual(exit_code({'results': [result]}), 1)
        self.assertEqual(exit_code({'results': [result | {'evidence_complete': False}]}), 2)
        self.assertEqual(exit_code({'results': []}), 2)
        self.assertEqual(exit_code({'results': [result | {'state': 'RUN_STATE_COMPLETED',
                                                         'all_eligible_units_audited': True}]}), 0)

    def test_checkpoint_retries_a_transient_lock_and_preserves_old_data_on_failure(self):
        original = Path.replace
        attempts = []

        def locked_once(source, target):
            attempts.append(source)
            if len(attempts) == 1:
                raise PermissionError('sharing violation')
            return original(source, target)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.json'
            save(path, {'old': True})
            with patch.object(Path, 'replace', locked_once), patch('audit_candidates.time.sleep'):
                save(path, {'new': True})
            self.assertEqual(len(attempts), 2)
            self.assertEqual(json.loads(path.read_text()), {'new': True})
            with patch.object(Path, 'replace', side_effect=PermissionError('locked')), \
                    patch('audit_candidates.time.sleep'), self.assertRaises(PermissionError):
                save(path, {'unpublished': True})
            self.assertEqual(json.loads(path.read_text()), {'new': True})


if __name__ == '__main__':
    unittest.main()
