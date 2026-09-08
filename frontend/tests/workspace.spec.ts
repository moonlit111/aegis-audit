import { test, expect, type Page } from '@playwright/test';
import { zipSync, strToU8 } from 'fflate';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '../..');

test('runtime configuration → repeated component observations → reload → factual report', async ({
  page,
}) => {
  test.skip(
    process.env.AEGIS_TEST_RUNTIME !== '1',
    'Run scripts/e2e.py --runtime with the runtime image installed',
  );
  const data = zipSync({ 'store.py': strToU8('DATA = {}\n\ndef fetch(name):\n    return DATA[name]\n') });
  const card = await importFile(page, '运行证据浏览器验证', 'runtime-ui.zip', Buffer.from(data));
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始结构分析', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await page.getByRole('tab', { name: '运行验证', exact: true }).click();
  const config = {
    mode: 'VERIFY',
    adapter: 'PYTHON_CALL',
    path: 'store.py',
    function: 'fetch',
    globals: { DATA: { public: 'hello', private: '{{canary}}' } },
    fixtures: [],
    baseline: { args: ['public'], kwargs: {}, stdin: '' },
    probe: { args: ['private'], kwargs: {}, stdin: '' },
    observer: 'RETURN_CANARY',
    marker_path: '',
    repeats: 2,
    timeout_seconds: 5,
  };
  await page.getByLabel('运行配置 JSON').fill(JSON.stringify(config));
  await page.getByRole('button', { name: '开始本地测试', exact: true }).click();
  await expect(page.locator('.runtime-record')).toContainText('组件内验证成立');
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
