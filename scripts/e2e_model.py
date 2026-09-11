"""Deterministic loopback-only provider for UI workflow tests, not model efficacy."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time


class FixtureProvider:
    def __init__(self):
        self.calls = []
        self.release_auditors = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                if self.path == '/__test__/release-auditors':
                    owner.release_auditors.set()
                    self.send_response(204)
                    self.end_headers()
                    return
                if self.path != '/v1/chat/completions':
                    self.send_error(404)
                    return
                if self.headers.get('Authorization') != 'Bearer browser-fixture-key':
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'Invalid key; browser-fixture-key must never be echoed by the app')
                    return
                length = int(self.headers.get('Content-Length', '0'))
                if length > 4 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = json.loads(self.rfile.read(length))
                assert not any(key in body for key in ('thinking', 'reasoning_effort', 'response_format'))
                messages = body['messages']
                if messages[0]['role'] != 'system':
                    role, context, result = 'CONNECTION_CHECK', {}, {'connected': True}
                else:
                    system = messages[0]['content']
                    role = 'REVERSE' if "AegisAudit's reverse-engineering agent" in system else next(
                        role for role in ('PLANNER', 'AUDITOR', 'REVIEWER', 'VERIFIER', 'REPORTER') if 'ROLE: ' + role in system)
                    context = json.loads(messages[1]['content'])
                    if role == 'REVERSE':
                        result = owner.reverse(messages, context)
                    else:
                        result = {'action': 'finish', 'result': owner.answer(role, context)}
                owner.calls.append({'role': role, 'human_reference_count': len(context.get('human_annotations', {}).get('items', []))})
                if role == 'AUDITOR':
                    # Keep the actual app workflow active until the test has inspected
                    # its phases, immutable interim export and configuration lock.
                    owner.release_auditors.wait(timeout=60)
                time.sleep(0.15)
                payload = json.dumps({'id': 'browser-fixture-response', 'choices': [{'message': {'content': json.dumps(result, ensure_ascii=False)}, 'finish_reason': 'stop'}],
                                      'usage': {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120}}, ensure_ascii=False).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}/v1'

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.release_auditors.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @staticmethod
    def reverse(messages, context):
        observations = []
        for message in messages[2:]:
            if message['role'] == 'user':
                try:
                    observation = json.loads(message['content'])
                except json.JSONDecodeError:
                    continue
                if 'tool' in observation:
                    observations.append(observation)
        if not observations:
            return {'action': 'tool', 'name': 'plan_recovery', 'arguments': {
                'assessment': '固定 PE 样本，使用实际 Ghidra 产物核对二进制规划入口。',
                'evidence': ['目标类型：' + context['program']['target']['kind']],
                'steps': [{'tool': 'ghidra', 'input': 'original', 'reason': '生成可定位的真实函数伪代码。'}],
                'limitations': ['测试只验证流程与产物，不评价模型判断能力。'],
            }}
        if observations[-1]['tool'] == 'plan_recovery':
            return {'action': 'tool', 'name': 'run_recovery_step', 'arguments': {}}
        result = observations[-1]['result']
        return {'action': 'finish', 'result': {
            'summary': '固定测试已读取恢复工具结果：' + str(result.get('status', '见原始执行记录')),
            'limitations': ['未执行动态漏洞验证。'],
        }}

    @staticmethod
    def answer(role, context):
        if role == 'PLANNER':
            if context['target']['kind'] == 'BINARY':
                unit = context['units'][0]
                return {'approach': '先按函数地址核对入口，再检查调用关系。',
                        'priorities': [{'unit_id': unit['unit_id'], 'reason': '从实际恢复的第一个函数建立调用上下文。'}],
                        'limitations': ['伪代码行号属于函数内映射，不等同于机器指令地址。']}
            priorities = [{'unit_id': unit['unit_id'], 'reason': '外部参数进入文件读取，先核对目录约束。'} for unit in context['units'] if unit['name'] == 'download']
            return {'approach': '先检查文件入口，再核对认证逻辑与模块代码。', 'priorities': priorities,
                    'limitations': ['固定脚本只验证产品流程，不代表真实模型审计能力。']}
        if role == 'AUDITOR':
            focus = context['focus']
            unit_id = focus['unit_id']
            findings, annotations = [], []
            if focus['name'] == 'download':
                number, quote = next(line.split('|', 1) for line in focus['numbered_code'].splitlines() if 'return open(' in line)
                findings.append({'title': '文件路径缺少目录约束', 'category': 'PATH_TRAVERSAL', 'cwe': 'CWE-22', 'severity': 'HIGH',
                                 'severity_reason': '外部参数直接到达文件读取', 'unit_id': unit_id, 'input_source': 'name 参数',
                                 'sink': 'open(name)', 'missing_guard': '未限制允许目录', 'preconditions': '调用者能控制文件名',
                                 'impact': '可能越过文档目录读取文件', 'recommendation': '规范化路径并验证允许目录',
                                 'evidence': [{'unit_id': unit_id, 'start_line': int(number), 'end_line': int(number), 'quote': quote}]})
            if focus['name'] == 'login':
                number, quote = next(line.split('|', 1) for line in focus['numbered_code'].splitlines() if 'return password' in line)
                annotations.append({'unit_id': unit_id, 'tag': 'AUTHENTICATION', 'rationale': '核对密码比较逻辑',
                                    'evidence': [{'unit_id': unit_id, 'start_line': int(number), 'end_line': int(number), 'quote': quote}]})
            return {'audited_unit_ids': [unit_id], 'findings': findings, 'annotations': annotations, 'limitations': []}
        if role == 'REVIEWER':
            evidence = context['candidate']['evidence']
            return {'verdict': 'VALIDATED', 'rationale': '原始函数直接读取参数路径', 'counter_evidence': '样本代码中没有目录检查',
                    'missing_information': '尚未验证部署入口', 'evidence': evidence,
                    'assessments': [{'check': check, 'status': 'SUPPORTED', 'rationale': '固定样本的原文支持此条件', 'evidence': evidence}
                                    for check in ('INPUT_CONTROL', 'REACHABILITY', 'DEFENSE_GAP')]}
        if role == 'VERIFIER':
            return {'status': 'NEEDS_CONFIGURATION', 'rationale': '需补充运行配置', 'limitations': ['未执行动态验证'], 'config': None}
        return {'summary': '固定测试样本的静态流程已完成', 'recommendations': ['核对真实部署入口'], 'limitations': ['未执行动态验证']}
