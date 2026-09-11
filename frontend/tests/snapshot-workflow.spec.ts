import { test, expect, type Page } from '@playwright/test';

const snapshot = {
  id: 'workflow-snapshot',
  projectId: 'workflow-project',
  name: 'workflow.exe',
  kind: 2,
  state: 2,
  targetSha256: 'a'.repeat(64),
  fileCount: '1',
  totalBytes: '1024',
  createdAt: '2026-09-11T10:00:00Z',
};
type Run = {
  id: string;
  snapshotId: string;
  projectId: string;
  scope: string;
  state: number;
  createdAt: string;
  unitCount: string;
  summaryJson: string;
};
const run = (id: string, scope = 'STRUCTURE_ANALYSIS', state = 2): Run => ({
  id,
  scope,
  state,
  snapshotId: snapshot.id,
  projectId: snapshot.projectId,
  createdAt: `2026-09-11T11:0${id.endsWith('2') ? '2' : '1'}:00Z`,
  unitCount: '2',
  summaryJson: '{}',
});

async function workspace(page: Page) {
  const state = { runs: [] as Run[], requests: [] as Record<string, unknown>[], failCreate: false };
  await page.route('**/rpc/**', async (route) => {
    const method = route.request().url().split('/').pop();
    let json: unknown = {};
    switch (method) {
      case 'ListProjects':
        json = { projects: [{ id: snapshot.projectId, name: '工作流验证', createdAt: snapshot.createdAt }] };
        break;
      case 'GetProject':
        json = { snapshots: [snapshot] };
        break;
      case 'GetSnapshot':
        json = { snapshot };
        break;
      case 'ListRuns':
        json = { runs: state.runs };
        break;
      case 'GetRun':
        json = {
          run: state.runs.find((r) => r.id === route.request().postDataJSON().runId),
          artifacts: [],
          phases: [],
        };
        break;
      case 'GetCapabilities':
        json = {
          version: '0.2.0',
          modelConnection: { configured: true },
          executors: [
            {
              id: 'fixture',
              capabilities: ['import', 'ghidra', 'tree-sitter'].map((name) => ({ name, available: true })),
            },
          ],
        };
        break;
      case 'WatchRun':
        await route.abort();
        return;
      case 'CreateRun': {
        const request = route.request().postDataJSON();
        state.requests.push(request);
        if (state.failCreate) {
          await route.fulfill({
            status: 503,
            contentType: 'application/json',
            json: { code: 'unavailable', message: '模拟响应中断，请重试' },
          });
          return;
        }
        const created = run(`round-${state.requests.length}`, request.scope);
        state.runs.unshift(created);
        json = { run: created };
        break;
      }
    }
    await route.fulfill({ status: 200, contentType: 'application/json', json });
  });
  return state;
}

test('snapshot workflow follows running and completed rounds, including reload and mobile', async ({
  page,
}, info) => {
  const state = await workspace(page);
  await page.goto('/');
  const card = page.locator('.snapshot-card');
  await expect(card).toContainText('无需先单独反编译');
  await expect(card.getByRole('button', { name: '开始漏洞审计', exact: true })).toBeVisible();
  await card.getByRole('button', { name: '仅反编译', exact: true }).click();
  await expect(page).toHaveURL(/runs\/round-1/);
  await page.goto('/#/projects');
  await expect(card.getByRole('link', { name: '查看进度', exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: /反编译|审计/ })).toHaveCount(0);
  await page.reload();
  await expect(card.getByRole('link', { name: '查看进度', exact: true })).toBeVisible();
  expect(state.requests).toHaveLength(1);
  state.runs[0].state = 5;
  await page.reload();
  await expect(card.getByRole('link', { name: '查看反编译结果', exact: true })).toBeVisible();
  await card.getByRole('button', { name: '继续漏洞审计', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '开始漏洞审计', exact: true });
  await expect(dialog).toContainText('兼容的已有反编译结果会自动复用');
  await expect(dialog.getByLabel('总模型调用上限')).not.toBeVisible();
  await dialog.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect(page).toHaveURL(/runs\/round-2/);
  await expect(page.getByRole('tab', { name: /^漏洞审计/ })).toHaveAttribute('aria-selected', 'true');
  expect(state.requests).toHaveLength(2);
  expect(state.requests[1].scope).toBe('SECURITY_AUDIT');
  state.runs[0].state = 5;
  await page.goto('/#/projects');
  await expect(card.getByRole('link', { name: '查看审计结果', exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: '重新审计', exact: true })).not.toBeVisible();
  await card.getByText('重新运行', { exact: true }).click();
  await expect(card.getByRole('button', { name: '重新审计', exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath('snapshot-workflow-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('snapshot-workflow-mobile.png'), fullPage: true });
});

test('snapshot workflow reuses a submission id after an error and distinguishes changed settings', async ({
  page,
}) => {
  const state = await workspace(page);
  state.failCreate = true;
  await page.goto('/');
  await page.locator('.snapshot-card').getByRole('button', { name: '开始漏洞审计', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '开始漏洞审计', exact: true });
  await dialog.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('模拟响应中断');
  await dialog.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect.poll(() => state.requests.length).toBe(2);
  expect(state.requests[0].requestId).toBe(state.requests[1].requestId);
  await dialog.getByText('高级设置：模型与预算', { exact: true }).click();
  await dialog.getByLabel('程序单元上限').fill('12');
  await dialog.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect.poll(() => state.requests.length).toBe(3);
  expect(state.requests[2].requestId).not.toBe(state.requests[1].requestId);
});

test('snapshot workflow notices a task started elsewhere while the audit dialog is open', async ({
  page,
}) => {
  const state = await workspace(page);
  await page.goto('/');
  await page.locator('.snapshot-card').getByRole('button', { name: '开始漏洞审计', exact: true }).click();
  state.runs = [run('elsewhere')];
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: '查看进度', exact: true })).toBeVisible();
  await dialog.getByRole('button', { name: '查看进度', exact: true }).click();
  await expect(page).toHaveURL(/runs\/elsewhere/);
  expect(state.requests).toHaveLength(0);
});
