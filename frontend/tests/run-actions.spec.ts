import { expect, test, type Page } from '@playwright/test';
import { RunState } from '../src/gen/audit/v1/audit_pb';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => (release = resolve));
  return { promise, release };
}
type ReportRequest = { requestId: string; runId: string; format: string };
type Report = {
  id: string;
  runId: string;
  artifactId: string;
  format: string;
  interim: boolean;
  snapshotState: string;
  snapshotAt: string;
};

async function workspace(page: Page) {
  const snapshot = {
    id: 'actions-snapshot',
    projectId: 'actions-project',
    name: 'PermitLedger.exe',
    kind: 2,
    state: 2,
    createdAt: '2026-09-11T10:00:00Z',
    targetSha256: 'a'.repeat(64),
    fileCount: '1',
    totalBytes: '1024',
  };
  const state = {
    run: {
      id: 'actions-run',
      snapshotId: snapshot.id,
      projectId: snapshot.projectId,
      scope: 'STRUCTURE_ANALYSIS',
      state: RunState.RUNNING,
      createdAt: snapshot.createdAt,
      unitCount: '0',
      summaryJson: '{}',
    },
    getRuns: 0,
    pollHold: undefined as { started: ReturnType<typeof gate>; finish: ReturnType<typeof gate> } | undefined,
    cancelGate: undefined as ReturnType<typeof gate> | undefined,
    cancelRequests: 0,
    cancelState: RunState.CANCELLING,
    failCancel: false,
    reportGate: undefined as ReturnType<typeof gate> | undefined,
    reportRequests: [] as ReportRequest[],
    reports: new Map<string, Report>(),
    loseReportResponse: false,
    interimOverride: false,
  };
  await page.route('**/rpc/**', async (route) => {
    const method = route.request().url().split('/').pop();
    let json: unknown = {};
    switch (method) {
      case 'ListProjects':
        json = {
          projects: [{ id: snapshot.projectId, name: '任务操作验证', createdAt: snapshot.createdAt }],
        };
        break;
      case 'GetProject':
        json = { snapshots: [snapshot] };
        break;
      case 'GetSnapshot':
        json = { snapshot };
        break;
      case 'ListRuns':
        json = { runs: [state.run] };
        break;
      case 'GetRun': {
        state.getRuns += 1;
        json = { run: { ...state.run }, phases: [], artifacts: [] };
        const hold = state.pollHold;
        if (hold) {
          state.pollHold = undefined;
          hold.started.release();
          await hold.finish.promise;
        }
        break;
      }
      case 'GetCapabilities':
        json = { version: '0.2.0', executors: [] };
        break;
      case 'WatchRun':
        await route.abort();
        return;
      case 'CancelRun':
        state.cancelRequests += 1;
        await state.cancelGate?.promise;
        if (state.failCancel) {
          await route.fulfill({ status: 503, json: { code: 'unavailable', message: '模拟取消响应中断' } });
          return;
        }
        state.run.state = state.cancelState;
        json = { run: state.run };
        break;
      case 'CreateReport': {
        const request = route.request().postDataJSON() as ReportRequest;
        state.reportRequests.push(request);
        await state.reportGate?.promise;
        if (!state.reports.has(request.requestId))
          state.reports.set(request.requestId, {
            id: `report-${state.reports.size + 1}`,
            artifactId: `actions-report-${state.reports.size + 1}`,
            runId: state.run.id,
            format: request.format,
            interim: state.interimOverride || state.run.state < RunState.COMPLETED,
            snapshotState: RunState[state.run.state],
            snapshotAt: snapshot.createdAt,
          });
        if (state.loseReportResponse) {
          await route.fulfill({ status: 503, json: { code: 'unavailable', message: '模拟报告响应丢失' } });
          return;
        }
        json = { report: state.reports.get(request.requestId) };
        break;
      }
      case 'ListReports':
        json = { reports: [...state.reports.values()], total: String(state.reports.size) };
        break;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json });
  });
  return state;
}

const cancelDialog = (page: Page) => page.getByRole('dialog', { name: '取消当前任务？', exact: true });

test('run actions confirm cancellation and show submission, stopping, and durable completion', async ({
  page,
}, info) => {
  const state = await workspace(page);
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  state.cancelGate = gate();
  await page.goto('/#/runs/actions-run');
  const button = page.getByRole('button', { name: '取消任务', exact: true });
  await expect(button).toBeVisible();
  await page.screenshot({ path: info.outputPath('run-actions-desktop.png'), fullPage: true });
  await button.click();
  await expect(cancelDialog(page)).toContainText('PermitLedger.exe');
  await expect(cancelDialog(page)).toContainText('已完成的分析结果和证据会保留');
  await page.screenshot({ path: info.outputPath('cancel-confirmation.png') });
  await cancelDialog(page).getByRole('button', { name: '继续任务', exact: true }).click();
  await expect(button).toBeFocused();
  await button.click();
  await page.keyboard.press('Escape');
  await expect(cancelDialog(page)).toHaveCount(0);
  expect(state.cancelRequests).toBe(0);
  await button.click();
  await cancelDialog(page)
    .getByRole('button', { name: '确认取消', exact: true })
    .evaluate((button: HTMLButtonElement) => {
      button.click();
      button.click();
    });
  await expect(page.locator('.cancel-feedback')).toContainText('正在提交取消请求');
  await expect(page.getByRole('button', { name: '提交取消中…', exact: true })).toBeDisabled();
  await expect.poll(() => state.cancelRequests).toBe(1);
  state.cancelGate.release();
  await expect(page.locator('.cancel-feedback')).toContainText('正在取消任务');
  await expect(page.getByRole('button', { name: '正在取消…', exact: true })).toBeDisabled();
  await page.reload();
  await expect(page.locator('.cancel-feedback')).toContainText('正在取消任务');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('cancelling-mobile.png'), fullPage: true });
  state.run.state = RunState.CANCELLED;
  await expect(page.locator('.run-status')).toHaveText('已取消');
  await expect(page.locator('.cancel-feedback')).toContainText('任务已取消');
  await expect(page.getByRole('region', { name: '报告导出', exact: true })).toContainText('保存取消前');
  await expect(page.getByRole('button', { name: '取消任务', exact: true })).toHaveCount(0);
  await page.reload();
  await expect(page.locator('.cancel-feedback')).toContainText('任务已取消');
  await page.setViewportSize({ width: 360, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(state.cancelRequests).toBe(1);
  expect(errors).toEqual([]);
});

test('run actions keep cancellation errors across polls and retry queued cancellation', async ({ page }) => {
  const state = await workspace(page);
  state.run.state = RunState.QUEUED;
  state.failCancel = true;
  await page.goto('/#/runs/actions-run');
  await page.getByRole('button', { name: '取消任务', exact: true }).click();
  await expect(cancelDialog(page)).toContainText('任务将从队列中取消');
  await cancelDialog(page).getByRole('button', { name: '确认取消', exact: true }).click();
  await expect(page.locator('.cancel-feedback[role="alert"]')).toContainText('模拟取消响应中断');
  const reads = state.getRuns;
  await expect.poll(() => state.getRuns).toBeGreaterThanOrEqual(reads + 2);
  await expect(page.locator('.cancel-feedback[role="alert"]')).toContainText('取消请求未确认');
  state.failCancel = false;
  state.cancelState = RunState.CANCELLED;
  await page.getByRole('button', { name: '重试取消', exact: true }).click();
  await expect(page.locator('.cancel-feedback')).toContainText('任务已取消');
  await expect(page.locator('.cancel-feedback')).not.toContainText('正在取消');
  expect(state.cancelRequests).toBe(2);
});

test('run actions do not let a stale poll undo acknowledged cancellation', async ({ page }) => {
  const state = await workspace(page);
  await page.goto('/#/runs/actions-run');
  await expect(page.locator('.run-status')).toHaveText('分析中');
  const hold = { started: gate(), finish: gate() };
  state.pollHold = hold;
  await hold.started.promise;
  await page.getByRole('button', { name: '取消任务', exact: true }).click();
  await cancelDialog(page).getByRole('button', { name: '确认取消', exact: true }).click();
  await expect(page.locator('.cancel-feedback')).toContainText('正在取消任务');
  const response = page.waitForResponse((response) => response.url().endsWith('/GetRun'));
  hold.finish.release();
  await (await response).finished();
  await expect(page.locator('.run-status')).toHaveText('正在取消');
  await expect(page.getByRole('button', { name: '正在取消…', exact: true })).toBeDisabled();
});

test('run actions respect task completion before and during cancellation', async ({ page }) => {
  const state = await workspace(page);
  await page.goto('/#/runs/actions-run');
  await page.getByRole('button', { name: '取消任务', exact: true }).click();
  state.run.state = RunState.COMPLETED;
  const updated = page.getByRole('dialog', { name: '任务状态已更新', exact: true });
  await expect(updated).toBeVisible();
  await expect(updated.getByRole('button', { name: '确认取消', exact: true })).toHaveCount(0);
  await updated.getByRole('button', { name: '返回任务', exact: true }).click();
  expect(state.cancelRequests).toBe(0);

  state.run.state = RunState.RUNNING;
  state.cancelState = RunState.COMPLETED;
  await page.reload();
  await page.getByRole('button', { name: '取消任务', exact: true }).click();
  await cancelDialog(page).getByRole('button', { name: '确认取消', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await expect(page.locator('.cancel-feedback')).toContainText('任务已结束 · 分析完成');
  await expect(page.locator('.cancel-feedback')).not.toContainText('任务已取消');
});

test('run actions export one labelled report with progress, download, and history', async ({
  page,
}, info) => {
  const state = await workspace(page);
  state.reportGate = gate();
  await page.goto('/#/runs/actions-run');
  const card = page.getByRole('region', { name: '报告导出', exact: true });
  await card.getByLabel('报告格式').selectOption('json');
  await card
    .getByRole('button', { name: '导出阶段报告', exact: true })
    .evaluate((button: HTMLButtonElement) => {
      button.click();
      button.click();
    });
  await expect(card.getByRole('status')).toContainText('正在生成 JSON 文件');
  await expect(card.getByLabel('报告格式')).toBeDisabled();
  await expect(card.getByRole('button', { name: '正在生成…', exact: true })).toBeDisabled();
  await expect.poll(() => state.reportRequests.length).toBe(1);
  state.reportGate.release();
  const downloadDialog = page.getByRole('dialog', { name: '下载文件确认', exact: true });
  await expect(downloadDialog).toContainText('PermitLedger.exe · JSON 阶段报告');
  const download = page.waitForEvent('download');
  await downloadDialog.getByRole('button', { name: '下载文件', exact: true }).click();
  // Mock reports have no stored artifact; workspace/capabilities tests verify the actual file bytes.
  expect((await download).url()).toBe(new URL('/api/artifacts/actions-report-1', page.url()).href);
  await (await download).cancel();
  await expect(card.getByRole('status')).toContainText('JSON 阶段报告已生成');
  await expect(card.getByLabel('报告格式')).toBeEnabled();
  await expect(page.locator('.run-status')).toHaveText('分析中');
  await card.getByRole('button', { name: '历史记录', exact: true }).click();
  await expect(page.getByRole('tab', { name: '报告历史', exact: true })).toHaveAttribute(
    'aria-selected',
    'true',
  );
  await expect(page.locator('.report-history tbody tr')).toHaveCount(1);
  await expect(page.locator('.report-history tbody tr')).toContainText('阶段报告');
  await page.screenshot({ path: info.outputPath('export-success.png'), fullPage: true });
});

test('run actions retain export errors and reuse the request after a lost response', async ({ page }) => {
  const state = await workspace(page);
  state.loseReportResponse = true;
  await page.goto('/#/runs/actions-run');
  const card = page.getByRole('region', { name: '报告导出', exact: true });
  await card.getByRole('button', { name: '导出阶段报告', exact: true }).click();
  await expect(card.getByRole('alert')).toContainText('模拟报告响应丢失');
  const reads = state.getRuns;
  await expect.poll(() => state.getRuns).toBeGreaterThanOrEqual(reads + 2);
  await expect(card.getByRole('alert')).toContainText('模拟报告响应丢失');
  state.loseReportResponse = false;
  await card.getByRole('button', { name: '重试导出', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  expect(state.reportRequests).toHaveLength(2);
  expect(state.reportRequests[0].requestId).toBe(state.reportRequests[1].requestId);
  expect(state.reports.size).toBe(1);
  await expect(card.getByRole('status')).toContainText('HTML 阶段报告已生成');
  await card.getByRole('button', { name: '下载', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('PermitLedger.exe · HTML 阶段报告');
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  expect(state.reportRequests).toHaveLength(2);
  await card.getByLabel('报告格式').selectOption('markdown');
  await card.getByRole('button', { name: '导出阶段报告', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('MARKDOWN 阶段报告');
  expect(state.reportRequests[2].requestId).not.toBe(state.reportRequests[1].requestId);
  expect(state.reports.size).toBe(2);
});

test('run actions describe incomplete results and use the server report type', async ({ page }) => {
  const state = await workspace(page);
  state.run.state = RunState.PARTIAL;
  // A terminal audit can still have a separate runtime verification in progress.
  state.interimOverride = true;
  await page.goto('/#/runs/actions-run');
  const card = page.getByRole('region', { name: '报告导出', exact: true });
  await expect(card).toContainText('包含已完成部分');
  await card.getByRole('button', { name: '导出报告', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('HTML 阶段报告');
  await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click();
  await expect(card.getByRole('status')).toContainText('HTML 阶段报告已生成');
});
