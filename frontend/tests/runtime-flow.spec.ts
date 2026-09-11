import { expect, test, type Page } from '@playwright/test';
import { RunState } from '../src/gen/audit/v1/audit_pb';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => (release = resolve));
  return { promise, release };
}

type RuntimeData = {
  id: string;
  runId: string;
  sourceRunId: string;
  findingId: string;
  status: string;
  createdAt: string;
  configJson: string;
  resultJson: string;
};
type CreateRequest = { requestId: string; sourceRunId: string; findingId?: string; configJson?: string };
const configuration = () => ({
  mode: 'VERIFY',
  adapter: 'WINDOWS_ORIGINAL_PE64',
  path: 'sample.exe',
  baseline: { args: ['baseline.bin'], kwargs: {}, stdin: '' },
  probe: { args: ['probe.bin'], kwargs: {}, stdin: '' },
  observer: 'SANITIZER',
  marker_path: '',
  repeats: 3,
  timeout_seconds: 5,
});

function result(scope = 'ORIGINAL', observed = true) {
  const trial = (label: string) => ({
    label,
    input_sha256: 'b'.repeat(64),
    exit_code: label === 'probe' && observed ? -1073741819 : 0,
    timed_out: false,
    processes_reaped: true,
    observed: label === 'probe' && observed,
    exception: '',
    stdout: '',
    stderr: '',
    truncated: false,
    crash_signature: label === 'probe' && observed ? 'NTSTATUS_C0000005' : '',
  });
  return {
    target_sha256: 'a'.repeat(64),
    config_hash: 'c'.repeat(64),
    image_id: 'fixture-windows',
    target_scope: scope,
    recipe_artifact_id: 'recipe',
    observation_artifact_id: 'observation',
    observation: {
      error: '',
      trials: [trial('baseline'), trial('probe'), trial('probe'), trial('probe')],
      build: { status: 'READY' },
      fuzz: {},
      crashes: [],
    },
    tools: [{ name: 'Windows', log_artifact_id: 'runtime-log' }],
  };
}

async function workspace(page: Page) {
  const snapshot = {
    id: 'runtime-snapshot',
    projectId: 'runtime-project',
    name: 'sample.exe',
    kind: 2,
    state: 2,
    createdAt: '2026-09-12T03:00:00Z',
    targetSha256: 'a'.repeat(64),
    fileCount: '1',
    totalBytes: '1024',
    metadataJson: JSON.stringify({ format: 'PE', architecture: 'x86_64' }),
  };
  const finding = {
    id: 'runtime-finding',
    runId: 'runtime-source',
    unitId: 'runtime-unit',
    title: '输入长度缺少校验',
    cwe: 'CWE-787',
    severity: 'HIGH',
    reviewStatus: 'VALIDATED',
    verificationStatus: 'NOT_RUN',
    revision: 1,
    staticScope: 'COMPONENT',
    evidence: [],
    missingGuard: '写入前未检查缓冲区边界',
    impact: '可能触发越界写入',
    recommendation: '写入前校验长度',
  };
  const state = {
    snapshot,
    run: {
      id: 'runtime-source',
      projectId: snapshot.projectId,
      snapshotId: snapshot.id,
      scope: 'SECURITY_AUDIT',
      state: RunState.COMPLETED,
      createdAt: snapshot.createdAt,
      unitCount: '1',
      summaryJson: JSON.stringify({ finding_count: 1, vulnerability_audit: 'COMPLETED' }),
    },
    finding,
    config: configuration() as Record<string, unknown>,
    taskStatus: 'SUCCEEDED',
    planStatus: 'READY',
    hasPlan: true,
    records: [] as RuntimeData[],
    requests: [] as CreateRequest[],
    auditReads: 0,
    createGate: undefined as ReturnType<typeof gate> | undefined,
    readHold: undefined as { started: ReturnType<typeof gate>; finish: ReturnType<typeof gate> } | undefined,
    cancelGate: undefined as ReturnType<typeof gate> | undefined,
    cancelRequests: 0,
    failCancel: false,
    failCreate: false,
    loseResponse: false,
    failReads: false,
    childError: '',
  };
  const created = new Map<string, RuntimeData>();
  const tasks = () =>
    state.hasPlan
      ? [
          {
            id: 'verification-plan',
            runId: state.run.id,
            itemKey: finding.id,
            role: 'VERIFIER',
            status: state.taskStatus,
            resultJson: JSON.stringify({
              status: state.planStatus,
              rationale: '分别运行正常输入与异常输入，比较程序行为。',
              limitations: ['本方案验证崩溃现象，未验证任意代码执行。'],
              config: state.planStatus === 'UNSUPPORTED' ? null : state.config,
            }),
          },
        ]
      : [];
  const childRun = (record: RuntimeData) => ({
    ...state.run,
    id: record.runId,
    scope: JSON.parse(record.configJson).mode === 'FUZZ' ? 'DYNAMIC_TESTING' : 'RUNTIME_VERIFICATION',
    state:
      (
        {
          QUEUED: RunState.QUEUED,
          WAITING_EXECUTOR: RunState.WAITING_EXECUTOR,
          RUNNING: RunState.RUNNING,
          CANCELLING: RunState.CANCELLING,
          CANCELLED: RunState.CANCELLED,
          ERROR: RunState.FAILED,
        } as Record<string, RunState>
      )[record.status] || RunState.COMPLETED,
    error: state.childError,
    summaryJson: JSON.stringify({
      source_run_id: state.run.id,
      verification: record.status,
      exploitation: ['REPRODUCED', 'VERIFIED_COMPONENT'].includes(record.status) ? 'COMPLETED' : 'NOT_RUN',
      ...(record.resultJson
        ? {
            exploitation_artifact_id: 'exploit-evidence',
            exploitation_input_artifact_id: 'replay-input',
            exploitation_runner_artifact_id: 'replay-script',
          }
        : {}),
    }),
  });
  await page.route('**/api/session', (route) => route.fulfill({ json: { csrf_token: 'runtime-fixture' } }));
  await page.route('**/rpc/**', async (route) => {
    const method = route.request().url().split('/').pop();
    let json: unknown = {};
    switch (method) {
      case 'ListProjects':
        json = {
          projects: [{ id: snapshot.projectId, name: '运行验证交互测试', createdAt: snapshot.createdAt }],
        };
        break;
      case 'GetProject':
        json = { snapshots: [snapshot] };
        break;
      case 'GetSnapshot':
        json = { snapshot };
        break;
      case 'ListRuns':
        json = { runs: [state.run, ...state.records.map(childRun)] };
        break;
      case 'GetRun': {
        const request = route.request().postDataJSON();
        const record = state.records.find((record) => record.runId === request.runId);
        json = {
          run: record ? childRun(record) : state.run,
          artifacts: [],
          phases: record
            ? [
                {
                  id: 'RUNTIME',
                  title: '动态执行与进程回收',
                  order: 1,
                  status: record.resultJson ? 'COMPLETED' : 'RUNNING',
                },
              ]
            : [
                {
                  id: 'VERIFICATION_PLAN',
                  title: '验证方案生成',
                  order: 1,
                  status: state.taskStatus === 'SUCCEEDED' && state.hasPlan ? 'COMPLETED' : 'RUNNING',
                  current: state.taskStatus === 'SUCCEEDED' ? '1' : '0',
                  total: '1',
                },
              ],
        };
        break;
      }
      case 'GetCapabilities':
        json = { version: '0.2.0', executors: [] };
        break;
      case 'WatchRun':
        await route.abort();
        return;
      case 'GetAudit': {
        state.auditReads += 1;
        json = structuredClone({
          findings: [finding],
          reviews: [],
          annotations: [],
          modelCalls: [],
          tasks: tasks(),
          runtime: state.records,
        });
        const hold = state.readHold;
        if (hold) {
          state.readHold = undefined;
          hold.started.release();
          await hold.finish.promise;
        }
        if (state.failReads) {
          await route.fulfill({
            status: 503,
            json: { code: 'unavailable', message: '验证记录读取暂时中断' },
          });
          return;
        }
        break;
      }
      case 'ListFindings':
        json = { findings: [finding], total: '1' };
        break;
      case 'GetFinding':
        json = { finding, reviews: [] };
        break;
      case 'ListRuntime':
        json = { records: state.records };
        break;
      case 'CreateRuntime': {
        const request = route.request().postDataJSON() as CreateRequest;
        state.requests.push(request);
        await state.createGate?.promise;
        if (!state.failCreate && !created.has(request.requestId)) {
          const config = request.configJson ? JSON.parse(request.configJson) : state.config;
          const record = {
            id: `record-${state.records.length + 1}`,
            runId: `verification-${state.records.length + 1}`,
            sourceRunId: state.run.id,
            findingId: request.findingId || '',
            status: 'QUEUED',
            createdAt: new Date(Date.UTC(2026, 8, 12, 3, state.records.length + 1)).toISOString(),
            // Persisted optional defaults and different object key order must
            // still identify the same plan after reload.
            configJson: JSON.stringify({
              function: '',
              fixtures: [],
              globals: {},
              fuzz: {
                engine: 'MUTATION',
                input_mode: 'STDIN',
                seeds: ['hello'],
                max_cases: 256,
                budget_seconds: 30,
                random_seed: 71413,
              },
              ...config,
            }),
            resultJson: '',
          };
          state.records.push(record);
          created.set(request.requestId, record);
        }
        if (state.failCreate || state.loseResponse) {
          await route.fulfill({
            status: 503,
            json: { code: 'unavailable', message: '模拟验证提交响应中断' },
          });
          return;
        }
        json = { record: created.get(request.requestId) };
        break;
      }
      case 'CancelRun': {
        state.cancelRequests += 1;
        await state.cancelGate?.promise;
        if (state.failCancel) {
          await route.fulfill({ status: 503, json: { code: 'unavailable', message: '模拟取消失败' } });
          return;
        }
        const request = route.request().postDataJSON();
        const record = state.records.find((record) => record.runId === request.runId)!;
        record.status = 'CANCELLING';
        json = { run: childRun(record) };
        break;
      }
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json });
  });
  return state;
}

const runtimeTab = (page: Page) => page.getByRole('tab', { name: '运行验证', exact: true });
const coverageTab = (page: Page) => page.getByRole('tab', { name: '覆盖与产物', exact: true });
const planPanel = (page: Page) => page.getByRole('region', { name: '验证方案与运行配置', exact: true });
const resultPanel = (page: Page) => page.getByRole('region', { name: '验证进度与结果', exact: true });

async function openPlan(page: Page) {
  await page.goto('/#/runs/runtime-source');
  await runtimeTab(page).click();
  await expect(planPanel(page).getByRole('button', { name: '按方案运行', exact: true })).toBeVisible();
}

test('runtime flow: hide verification until the plan arrives, including background completion', async ({
  page,
}) => {
  const state = await workspace(page);
  state.hasPlan = false;
  state.run.state = RunState.RUNNING;
  await page.goto('/#/runs/runtime-source');
  await expect(page.getByRole('heading', { name: state.finding.title })).toBeVisible();
  await expect(runtimeTab(page)).toHaveCount(0);
  await expect(page.getByRole('button', { name: '查看验证方案', exact: true })).toHaveCount(0);
  await coverageTab(page).click();
  await expect(resultPanel(page)).toHaveCount(0);
  state.hasPlan = true;
  state.taskStatus = 'RUNNING';
  const reads = state.auditReads;
  await expect.poll(() => state.auditReads).toBeGreaterThan(reads);
  await expect(runtimeTab(page)).toHaveCount(0);
  state.taskStatus = 'SUCCEEDED';
  state.run.state = RunState.COMPLETED;
  await expect(runtimeTab(page)).toBeVisible();
  await expect(resultPanel(page)).toContainText('尚未启动运行');
  await page
    .getByRole('region', { name: '任务阶段', exact: true })
    .getByRole('button', { name: /验证方案生成/ })
    .click();
  await expect(runtimeTab(page)).toHaveAttribute('aria-selected', 'true');
  await expect(planPanel(page)).toContainText('尚未执行');
  expect(state.requests).toHaveLength(0);
});

test('runtime flow: one click shows submission then focuses coverage before slow reads finish', async ({
  page,
}, info) => {
  const state = await workspace(page);
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await openPlan(page);
  const readHold = { started: gate(), finish: gate() };
  state.readHold = readHold;
  await planPanel(page).getByRole('button', { name: '刷新验证方案', exact: true }).click();
  await readHold.started.promise;
  state.createGate = gate();
  await planPanel(page)
    .getByRole('button', { name: '按方案运行', exact: true })
    .evaluate((button: HTMLButtonElement) => {
      button.click();
      button.click();
    });
  await expect(planPanel(page).getByRole('button', { name: '正在提交验证…', exact: true })).toBeDisabled();
  await expect(planPanel(page).getByRole('status')).toContainText('提交成功后将自动切换');
  await expect.poll(() => state.requests.length).toBe(1);
  state.createGate.release();
  await expect(coverageTab(page)).toHaveAttribute('aria-selected', 'true');
  await expect(resultPanel(page)).toContainText('验证已提交，正在排队');
  await expect(resultPanel(page).getByRole('heading', { name: '验证进度与结果', exact: true })).toBeFocused();
  expect(
    await resultPanel(page)
      .getByRole('heading', { name: '验证进度与结果' })
      .evaluate((node) => node.getBoundingClientRect().top),
  ).toBeLessThan(200);
  await expect(planPanel(page)).toHaveCount(0);
  readHold.finish.release();
  await expect(page.locator('.runtime-record.featured')).toHaveAttribute('data-record-id', 'record-1');
  await expect(page.locator('.runtime-record.featured')).toContainText('排队中');
  state.records[0].status = 'RUNNING';
  await expect(resultPanel(page)).toContainText('正在执行验证');
  await runtimeTab(page).click();
  await expect(planPanel(page).getByRole('button', { name: '运行中', exact: true })).toBeDisabled();
  await expect(planPanel(page).getByRole('button', { name: '按方案运行', exact: true })).toHaveCount(0);
  await planPanel(page).getByRole('button', { name: '查看验证进度', exact: true }).click();
  await page.screenshot({ path: info.outputPath('verification-running-desktop.png') });
  state.records[0].status = 'REPRODUCED';
  state.records[0].resultJson = JSON.stringify(result());
  await expect(resultPanel(page)).toContainText('原始程序复现成功');
  await expect(resultPanel(page)).toContainText('3 / 3 次触发');
  await expect(resultPanel(page)).toContainText('NTSTATUS_C0000005');
  await expect(resultPanel(page)).toContainText('未证明任意代码执行');
  await expect(resultPanel(page).getByRole('link', { name: '复放脚本', exact: true })).toHaveAttribute(
    'href',
    /replay-script/,
  );
  await page.screenshot({ path: info.outputPath('verification-result-desktop.png'), fullPage: true });
  await runtimeTab(page).click();
  await expect(planPanel(page).getByRole('button', { name: '查看验证结果', exact: true })).toBeVisible();
  await expect(planPanel(page).getByRole('button', { name: '按方案运行', exact: true })).toHaveCount(0);
  expect(state.requests).toHaveLength(1);
  expect(errors).toEqual([]);
});

test('runtime flow: failed submission remains visible across polls and retries the same request', async ({
  page,
}) => {
  const state = await workspace(page);
  state.failCreate = true;
  await openPlan(page);
  await planPanel(page).getByRole('button', { name: '按方案运行', exact: true }).click();
  const error = planPanel(page).getByRole('alert');
  await expect(error).toContainText('验证提交未确认');
  await expect(error).toBeFocused();
  const reads = state.auditReads;
  for (let index = 0; index < 2; index += 1) {
    await planPanel(page).getByRole('button', { name: '刷新验证方案', exact: true }).click();
    await expect.poll(() => state.auditReads).toBeGreaterThan(reads + index);
    await expect(error).toContainText('模拟验证提交响应中断');
  }
  state.failCreate = false;
  await error.getByRole('button', { name: '重试提交', exact: true }).click();
  await expect(resultPanel(page)).toContainText('验证已提交');
  expect(state.requests).toHaveLength(2);
  expect(state.requests[1].requestId).toBe(state.requests[0].requestId);
  expect(state.records).toHaveLength(1);
});

test('runtime flow: lost create response is recovered without a duplicate and reload retains results', async ({
  page,
}) => {
  const state = await workspace(page);
  state.loseResponse = true;
  await openPlan(page);
  await planPanel(page).getByRole('button', { name: '按方案运行', exact: true }).click();
  await expect(planPanel(page).getByRole('alert')).toContainText('验证提交未确认');
  state.loseResponse = false;
  await planPanel(page).getByRole('button', { name: '刷新验证方案', exact: true }).click();
  await expect(planPanel(page).getByRole('button', { name: '查看验证进度', exact: true })).toBeVisible();
  await planPanel(page).getByRole('button', { name: '重试提交', exact: true }).click();
  await expect(resultPanel(page)).toContainText('验证已提交');
  expect(state.requests).toHaveLength(1);
  await page.reload();
  await runtimeTab(page).click();
  await expect(planPanel(page).getByRole('button', { name: '排队中', exact: true })).toBeDisabled();
  await expect(planPanel(page).getByRole('button', { name: '按方案运行', exact: true })).toHaveCount(0);
  await planPanel(page).getByRole('button', { name: '查看验证进度', exact: true }).click();
  state.records[0].status = 'NOT_REPRODUCED';
  state.records[0].resultJson = JSON.stringify(result('ORIGINAL', false));
  await expect(resultPanel(page)).toContainText('本次未复现');
  await resultPanel(page).getByRole('link', { name: '打开验证任务', exact: true }).click();
  await expect(coverageTab(page)).toHaveAttribute('aria-selected', 'true');
  await expect(resultPanel(page)).toContainText('本次未复现');
  await resultPanel(page).getByRole('button', { name: '查看任务事件', exact: true }).click();
  await expect(page.getByRole('tab', { name: /^任务事件/ })).toHaveAttribute('aria-selected', 'true');
  await coverageTab(page).click();
  await expect(resultPanel(page).getByRole('link', { name: '原始分析', exact: true })).toHaveAttribute(
    'href',
    '#/runs/runtime-source',
  );
  expect(state.records).toHaveLength(1);
});

for (const scenario of [
  {
    status: 'VERIFIED_COMPONENT',
    scope: 'COMPONENT',
    title: '组件内复现成功',
    detail: '尚不能据此确认完整程序中的利用效果',
  },
  { status: 'NOT_REPRODUCED', scope: 'ORIGINAL', title: '本次未复现', detail: '不能证明漏洞不存在' },
  { status: 'INCONCLUSIVE', scope: 'ORIGINAL', title: '验证结论不确定', detail: '不足以形成明确的复现结论' },
  { status: 'ERROR', scope: 'ORIGINAL', title: '验证执行失败', detail: '尚不能判断是否复现' },
]) {
  test(`runtime flow: explain ${scenario.status} without overstating exploitation`, async ({ page }) => {
    const state = await workspace(page);
    const observation = result(scenario.scope, scenario.status === 'VERIFIED_COMPONENT');
    if (scenario.status === 'ERROR') {
      observation.observation.error = '测试入口加载失败';
      state.childError = '运行器未能加载测试入口';
    }
    state.records.push({
      id: 'existing-record',
      runId: 'existing-verification',
      sourceRunId: state.run.id,
      findingId: state.finding.id,
      status: scenario.status,
      createdAt: '2026-09-12T03:01:00Z',
      configJson: JSON.stringify(state.config),
      resultJson: JSON.stringify(observation),
    });
    await page.goto('/#/runs/runtime-source');
    await page.getByRole('button', { name: '查看验证结果', exact: true }).click();
    await expect(resultPanel(page).locator('.runtime-verdict')).toContainText(scenario.title);
    await expect(resultPanel(page).locator('.runtime-verdict')).toContainText(scenario.detail);
    if (scenario.status === 'ERROR') await expect(resultPanel(page)).toContainText('测试入口加载失败');
    await expect(resultPanel(page).locator('tbody tr')).toHaveCount(4);
    expect(state.requests).toHaveLength(0);
  });
}

test('runtime flow: desktop results preserve history and keep scope limitations', async ({ page }, info) => {
  const state = await workspace(page);
  state.records.push({
    id: 'old-fuzz',
    runId: 'old-fuzz-run',
    sourceRunId: state.run.id,
    findingId: state.finding.id,
    status: 'NO_CRASH_OBSERVED',
    createdAt: '2026-09-12T02:00:00Z',
    configJson: JSON.stringify({ ...state.config, mode: 'FUZZ' }),
    resultJson: JSON.stringify({
      ...result('INSTRUMENTED_BUILD', false),
      observation: { error: '', trials: [], build: {}, fuzz: { executions: 400, timeouts: 0 }, crashes: [] },
    }),
  });
  await openPlan(page);
  await planPanel(page).getByRole('button', { name: '按方案运行', exact: true }).click();
  await expect(resultPanel(page)).toContainText('验证已提交');
  state.records[1].status = 'WAITING_EXECUTOR';
  await expect(resultPanel(page)).toContainText('验证已提交，等待执行器');
  await page.screenshot({ path: info.outputPath('verification-waiting-desktop.png') });
  state.records[1].status = 'REPRODUCED';
  state.records[1].resultJson = JSON.stringify(result());
  await expect(page.locator('.runtime-record.featured')).toContainText('原始程序复现成功');
  await expect(page.locator('.runtime-record.featured')).toHaveAttribute('data-record-id', 'record-2');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('verification-history-desktop.png'), fullPage: true });
  await page.locator('.runtime-history > summary').click();
  await expect(page.locator('[data-record-id="old-fuzz"]')).toContainText('本次未观察到崩溃');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(state.requests).toHaveLength(1);
});

test('runtime flow: cancel feedback survives polling and disables duplicate cancellation', async ({
  page,
}) => {
  const state = await workspace(page);
  await openPlan(page);
  await planPanel(page).getByRole('button', { name: '按方案运行', exact: true }).click();
  await expect(resultPanel(page)).toContainText('验证已提交');
  state.failCancel = true;
  await resultPanel(page).getByRole('button', { name: '取消运行', exact: true }).click();
  await expect(resultPanel(page).getByRole('alert')).toContainText('取消请求未确认');
  const reads = state.auditReads;
  await expect.poll(() => state.auditReads).toBeGreaterThan(reads + 1);
  await expect(resultPanel(page).getByRole('alert')).toContainText('模拟取消失败');
  state.failCancel = false;
  state.cancelGate = gate();
  await resultPanel(page).getByRole('button', { name: '取消运行', exact: true }).click();
  await expect(resultPanel(page).getByRole('button', { name: '正在提交取消…', exact: true })).toBeDisabled();
  state.cancelGate.release();
  await expect(resultPanel(page)).toContainText('正在停止验证');
  await expect(resultPanel(page).getByRole('button', { name: '正在取消…', exact: true })).toBeDisabled();
  state.records[0].status = 'CANCELLED';
  await expect(resultPanel(page)).toContainText('验证已取消');
  await expect(resultPanel(page).getByRole('button', { name: '取消运行', exact: true })).toHaveCount(0);
  expect(state.cancelRequests).toBe(2);
});

test('runtime flow: an unsupported plan is visible but cannot start a run', async ({ page }) => {
  const state = await workspace(page);
  state.planStatus = 'UNSUPPORTED';
  await page.goto('/#/runs/runtime-source');
  await runtimeTab(page).click();
  await expect(planPanel(page)).toContainText('当前环境不支持');
  await expect(planPanel(page).getByRole('button', { name: '按方案运行', exact: true })).toHaveCount(0);
  expect(state.requests).toHaveLength(0);
});
