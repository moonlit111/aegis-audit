import { test, expect, type Page } from '@playwright/test';
import { zipSync, strToU8 } from 'fflate';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../..');

test('runtime configuration → repeated component observations → reload → factual report', async ({
  page,
}) => {
  test.setTimeout(240_000);
  test.skip(
    process.env.AEGIS_TEST_RUNTIME !== '1',
    'Run scripts/e2e.py --runtime with Windows host runtime tools installed',
  );
  const data = zipSync({
    'store.py': strToU8(
      'from pathlib import Path\n\nsettings = {}\n\ndef fetch(count, values, *, name):\n    assert type(count) is int and count == 7\n    assert values == [True, None, {"key": "value"}]\n    assert settings == {"enabled": True}\n    if name == "private":\n        Path("marker.txt").write_text("created", encoding="ascii")\n    return name\n',
    ),
  });
  const card = await importFile(page, '运行证据浏览器验证', 'runtime-ui.zip', Buffer.from(data));
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始结构分析', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await page.getByRole('tab', { name: '运行验证', exact: true }).click();
  const config = {
    mode: 'VERIFY',
    adapter: 'WINDOWS_PYTHON_CALL',
    path: 'store.py',
    function: 'fetch',
    globals: { settings: { enabled: true } },
    fixtures: [],
    baseline: { args: [7, [true, null, { key: 'value' }]], kwargs: { name: 'public' }, stdin: '' },
    probe: { args: [7, [true, null, { key: 'value' }]], kwargs: { name: 'private' }, stdin: '' },
    observer: 'FILE_CREATED',
    marker_path: 'marker.txt',
    repeats: 2,
    timeout_seconds: 5,
  };
  await page.getByLabel('运行配置 JSON').fill(JSON.stringify(config));
  await page.getByRole('button', { name: '开始本地测试', exact: true }).click();
  await expect(page.locator('.runtime-record')).toContainText('组件内验证成立', {
    timeout: 180_000,
  });
  await expect(page.locator('.runtime-record tbody tr')).toHaveCount(3);
  await page.reload();
  await page.getByRole('tab', { name: '运行验证', exact: true }).click();
  await expect(page.locator('.runtime-record')).toContainText('组件内验证成立');
  await page.getByLabel('报告格式').selectOption('json');
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: '导出报告', exact: true }).click();
  const report = JSON.parse(await readFile((await (await downloaded).path())!, 'utf8'));
  expect(report.checks.runtime_verification).toBe('COMPLETED');
  expect(report.checks.exploitation).toBe('NOT_RUN');
  expect(report.audit.runtime[0].result.target_scope).toBe('COMPONENT');
  expect(report.audit.runtime[0].result.observation.trials).toHaveLength(3);
  const trials = report.audit.runtime[0].result.observation.trials;
  expect(JSON.parse(trials[0].input_json)).toEqual(config.baseline);
  expect(JSON.parse(trials[1].input_json)).toEqual(config.probe);
});

async function importFile(page: Page, project: string, name: string, bytes: Buffer, binary = false) {
  await page.goto('/');
  await page.getByRole('button', { name: '新建项目', exact: true }).click();
  await page.getByLabel('项目名称', { exact: true }).fill(project);
  if (binary) await page.getByRole('button', { name: 'PE / ELF', exact: true }).click();
  await page
    .getByLabel(binary ? '选择二进制文件' : '选择 ZIP 文件', { exact: true })
    .setInputFiles({ name, mimeType: 'application/octet-stream', buffer: bytes });
  await page.getByRole('button', { name: '导入并创建快照', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  return page.locator('.snapshot-card').filter({ has: page.getByRole('heading', { name, exact: true }) });
}

test('ZIP → source positions → inferred graph → reports → event replay after refresh', async ({
  page,
}, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const data = zipSync({
    '源码/处理.py': strToU8(
      'def helper(value):\n    return value + 1\n\n\ndef entry():\n    return helper(7)\n',
    ),
    'helper.c': strToU8('int clamp(int x) { if (x < 0) return 0; return x; }\n'),
    'future.ts': strToU8('export const later = 1;\n'),
    '.git/config': strToU8('excluded metadata'),
    'README.md': strToU8('Functional fixture, not a vulnerability evaluation target.'),
  });
  const card = await importFile(page, '浏览器源码验证', 'source-ui.zip', Buffer.from(data));
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始结构分析', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('部分完成');
  await page.getByLabel('语言筛选').selectOption('python');
  await page.getByLabel('搜索函数或文件').fill('entry');
  await expect(page.locator('.unit-row')).toHaveCount(1);
  await page.locator('.unit-row').click();
  await expect(page.locator('.unit-meta')).toContainText('原文件 L5–L6');
  await expect(page.locator('.monaco-editor .view-lines')).toContainText('helper(7)');
  await page.screenshot({ path: testInfo.outputPath('source-view.png'), fullPage: true });
  await page.getByRole('tab', { name: '调用图', exact: true }).click();
  await expect(page.locator('.relation-list')).toContainText('推断');
  await expect(page.locator('.relation-list')).toContainText('helper');
  await page.getByRole('tab', { name: '覆盖与产物' }).click();
  await expect(page.getByRole('row').filter({ hasText: 'future.ts' })).toContainText('不支持');
  await page.getByText('导入时排除的文件或目录', { exact: false }).click();
  await expect(page.getByRole('row').filter({ hasText: '.git/config' })).toBeVisible();
  for (const format of ['json', 'html', 'markdown']) {
    await page.getByLabel('报告格式').selectOption(format);
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: '导出报告', exact: true }).click();
    const download = await downloaded;
    const content = await readFile((await download.path())!, 'utf8');
    expect(content).toContain('NOT_RUN');
    if (format === 'json') {
      const report = JSON.parse(content);
      expect(report.checks.exploitation).toBe('NOT_RUN');
      expect(report.run.state).toBe('PARTIAL');
      expect(report.units).toHaveLength(5);
      expect(report.artifacts.length).toBeGreaterThan(2);
    }
  }
  await page.getByRole('tab', { name: '任务事件' }).click();
  await expect(page.locator('.event-list')).toContainText('RUN_COMPLETED');
  const before = await page.locator('.event-seq').allTextContents();
  const url = page.url();
  await page.reload();
  await page.getByRole('tab', { name: '任务事件' }).click();
  await expect(page.locator('.event-list')).toContainText('RUN_COMPLETED');
  expect(await page.locator('.event-seq').allTextContents()).toEqual(before);
  expect(page.url()).toBe(url);
  expect(errors).toEqual([]);
});

test('browser folder import uses the same persistent structure pipeline', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: '新建项目', exact: true }).click();
  await page.getByLabel('项目名称', { exact: true }).fill('本地文件夹验证');
  await page.getByRole('button', { name: '本地文件夹', exact: true }).click();
  await page
    .getByLabel('选择文件夹', { exact: true })
    .setInputFiles(path.join(root, 'tests/fixtures/source'));
  await expect(page.locator('.drop-zone')).toContainText('5 个文件');
  await page.getByRole('button', { name: '导入并创建快照' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  const card = page.locator('.snapshot-card').filter({ hasText: 'source.zip' });
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始结构分析' }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await expect(page.locator('.explorer-title')).toContainText('11');
  await page.reload();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await expect(page.locator('.unit-row')).toHaveCount(11);
});

test('real Ghidra run survives stream loss and refresh; explicit cancellation is durable', async ({
  page,
}, testInfo) => {
  test.skip(process.env.AEGIS_SKIP_GHIDRA === '1', 'Ghidra is not configured in this environment');
  const fixture = await readFile(path.join(root, 'tests/fixtures/binary/sample-pe64.exe'));
  const card = await importFile(page, '二进制浏览器验证', 'target.exe', fixture, true);
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await page.route('**/audit.v1.RunService/WatchRun', (route) => route.abort('connectionfailed'));
  await card.getByRole('button', { name: '开始反编译' }).click();
  await expect(page.locator('.run-status')).toHaveText('分析中');
  await page.reload();
  await expect(page.locator('.run-status')).toHaveText('分析完成', { timeout: 60_000 });
  await page.unroute('**/audit.v1.RunService/WatchRun');
  await expect(page.locator('.unit-meta')).toContainText('入口 0x');
  await expect(page.locator('.unit-meta')).toContainText('RVA 0x');
  await expect(page.locator('.monaco-editor .view-lines')).not.toBeEmpty();
  await page.screenshot({ path: testInfo.outputPath('binary-view.png'), fullPage: true });
  await page.getByRole('tab', { name: '任务事件' }).click();
  await expect(page.locator('.event-list')).toContainText('RUN_COMPLETED');
  const sequence = await page.locator('.event-seq').allTextContents();
  expect(new Set(sequence).size).toBe(sequence.length);
  await page.getByRole('link', { name: '项目与快照' }).click();
  await page
    .locator('.snapshot-card')
    .filter({ hasText: 'target.exe' })
    .getByRole('button', { name: '开始反编译' })
    .click();
  await expect(page.locator('.run-status')).toHaveText('分析中');
  await page.getByRole('button', { name: '取消任务', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('已取消');
  await page.reload();
  await expect(page.locator('.run-status')).toHaveText('已取消');
});

test('invalid ZIP paths and unrecognized binaries fail visibly without an analysis action', async ({
  page,
}) => {
  const maliciousPath = Buffer.from(zipSync({ '../escape.py': strToU8('print(1)') }));
  const card = await importFile(page, '导入边界验证', 'unsafe.zip', maliciousPath);
  await expect(card.getByText('导入失败', { exact: true })).toBeVisible();
  await expect(card.locator('.inline-error')).toContainText('path traversal');
  await expect(card.getByRole('button', { name: '开始结构分析' })).toBeDisabled();
  const invalid = await importFile(page, '文件格式验证', 'invalid.exe', Buffer.from('not a PE file'), true);
  await expect(invalid.getByText('导入失败', { exact: true })).toBeVisible();
  await expect(invalid.locator('.inline-error')).toContainText('unsupported binary format');
  await expect(invalid.getByRole('button', { name: '开始反编译' })).toBeDisabled();
  await expect(invalid.getByRole('button', { name: '开始漏洞审计' })).toBeDisabled();
});

test('audit budget dialog submits explicit limits and stays usable on mobile', async ({ page }, testInfo) => {
  await page.route('**/audit.v1.SystemService/GetCapabilities', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.modelConnection = { ...body.modelConnection, configured: true };
    await route.fulfill({ response, json: body });
  });
  let submitted: Record<string, unknown> | undefined;
  await page.route('**/audit.v1.RunService/CreateRun', async (route) => {
    submitted = route.request().postDataJSON();
    await route.fulfill({
      status: 400,
      contentType: 'application/json',
      json: { code: 'failed_precondition', message: 'UI transport test: no model request was sent' },
    });
  });
  const data = zipSync({ 'small.py': strToU8('def value():\n    return 1\n') });
  const card = await importFile(page, '审计预算界面验证', 'small.zip', Buffer.from(data));
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始漏洞审计', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '审计预算' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('总模型调用上限')).toHaveValue('240');
  await expect(dialog.getByLabel('单次输出预算（0 = 不限制）')).toHaveValue('0');
  await expect(dialog.getByLabel('每个子任务工具轮数')).toHaveValue('24');
  await expect(dialog.getByLabel('任务时限（秒）', { exact: true })).toHaveValue('10800');
  await expect(dialog.getByLabel('单次模型时限（秒）')).toHaveValue('900');
  await dialog.getByLabel('思考强度').selectOption('max');
  await dialog.getByLabel('单次输出预算（0 = 不限制）').fill('131072');
  await dialog.getByLabel('总模型调用上限').fill('1000');
  await dialog.getByLabel('每个子任务工具轮数').fill('48');
  await dialog.getByLabel('程序单元上限').fill('25');
  await dialog.getByLabel('任务时限（秒）', { exact: true }).fill('21600');
  await dialog.getByLabel('单次模型时限（秒）').fill('1800');
  await dialog.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('no model request was sent');
  expect(submitted).toMatchObject({
    scope: 'SECURITY_AUDIT',
    maxModelCalls: 1000,
    maxUnits: 25,
    maxToolRounds: 48,
    timeoutSeconds: 21600,
    maxOutputTokens: 131072,
    reasoningEffort: 'max',
    modelTimeoutSeconds: 1800,
  });
  await dialog.getByRole('button', { name: '恢复默认预算' }).click();
  await expect(dialog.getByLabel('思考强度')).toHaveValue('high');
  await expect(dialog.getByLabel('总模型调用上限')).toHaveValue('240');
  await expect(dialog.getByLabel('单次输出预算（0 = 不限制）')).toHaveValue('0');
  await page.screenshot({ path: testInfo.outputPath('audit-budget-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  const bounds = await dialog.boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  expect(await dialog.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('audit-budget-mobile.png'), fullPage: true });
  await dialog.getByRole('button', { name: '开始审计', exact: true }).scrollIntoViewIfNeeded();
  await expect(dialog.getByRole('button', { name: '开始审计', exact: true })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
});
