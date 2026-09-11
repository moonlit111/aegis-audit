import { expect, test } from '@playwright/test';
import { zipSync, strToU8 } from 'fflate';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

test.use({ actionTimeout: 20_000 });

test.afterEach(async ({ request }) => {
  const endpoint = process.env.AEGIS_E2E_MODEL_ENDPOINT;
  if (endpoint) await request.post(new URL('/__test__/release-auditors', endpoint).toString());
});

test('web model settings → human references → typed phases and plan → review queue → interim history', async ({
  page,
}, testInfo) => {
  test.setTimeout(180_000);
  const endpoint = process.env.AEGIS_E2E_MODEL_ENDPOINT;
  test.skip(!endpoint, 'Requires scripts/e2e.py and its isolated loopback provider');
  const errors: string[] = [];
  const forbidden: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('response', (response) => {
    if (response.status() === 403 && response.url().includes('/rpc/')) forbidden.push(response.url());
  });
  await page.route('**/api/session', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 350));
    await route.continue();
  });
  await page.goto('/#/environment');
  await page.getByRole('button', { name: '配置模型连接', exact: true }).click();
  await page.getByLabel('接口类型').selectOption('OPENAI_COMPATIBLE');
  await page.getByLabel('API 基础地址').fill(endpoint!);
  await page.getByLabel('模型标识').fill('browser-fixture-model');
  await page.getByLabel('API Key', { exact: true }).fill('browser-fixture-key');
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.locator('.model-panel')).toContainText('网页保存（Windows 加密）');
  await page.getByRole('button', { name: '检测连接', exact: true }).click();
  await expect(page.locator('.model-panel')).toContainText('调用已验证');
  await page.reload();
  await expect(page.locator('.model-panel')).toContainText('browser-fixture-model');
  await page.getByRole('button', { name: '编辑模型连接', exact: true }).click();
  await page.getByLabel('密钥处理').selectOption('REPLACE');
  await expect(page.getByLabel('API Key', { exact: true })).toHaveValue('');
  await page.getByRole('button', { name: '取消编辑' }).click();
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('browser-fixture-key');
  await page.screenshot({ path: testInfo.outputPath('model-connection.png'), fullPage: true });

  await page.goto('/#/projects');
  await page.getByRole('button', { name: '导入新项目', exact: true }).click();
  await page.getByLabel('项目名称', { exact: true }).fill('能力闭环浏览器验证');
  const zip = zipSync({
    'review.py': strToU8(
      'def download(name):\n    return open(name, encoding="utf-8").read()\n\ndef login(password, expected):\n    return password == expected\n',
    ),
  });
  await page
    .getByLabel('选择 ZIP 文件', { exact: true })
    .setInputFiles({ name: 'capability-fixture.zip', mimeType: 'application/zip', buffer: Buffer.from(zip) });
  await page.getByRole('button', { name: '导入并创建快照', exact: true }).click();
  const card = page.locator('.snapshot-card').filter({ hasText: 'capability-fixture.zip' });
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '仅结构分析', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成');
  await page.getByRole('tab', { name: '关键逻辑', exact: true }).click();
  await page.getByRole('button', { name: '新建人工标注', exact: true }).click();
  await page.getByLabel('搜索标注单元').fill('login');
  await expect(page.getByLabel('标注程序单元').locator('option')).toHaveCount(1);
  await page.getByLabel('标注依据', { exact: true }).fill('人工上下文标记：后续审计须独立核对密码比较');
  await page.getByRole('button', { name: '保存人工标注', exact: true }).click();
  await expect(page.locator('.annotation-list')).toContainText('人工上下文标记');

  await page.goto('/#/projects');
  await card.getByRole('button', { name: '开始漏洞审计', exact: true }).click();
  await page.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect(page).toHaveURL(/#\/runs\//);
  const runUrl = page.url();
  await expect(page.locator('.workflow-progress li.current')).toContainText('逐单元审计与复核');
  await expect(page.getByRole('region', { name: '顶层审计规划' })).toContainText('先检查文件入口');
  await expect(page.getByRole('region', { name: '顶层审计规划' })).toContainText('外部参数进入文件读取');
  await page.reload();
  await expect(page.locator('.workflow-progress li.current')).toContainText('逐单元审计与复核');
  await expect(page.getByRole('region', { name: '顶层审计规划' })).toContainText('外部参数进入文件读取');
  await page.screenshot({ path: testInfo.outputPath('active-phases-and-plan.png'), fullPage: true });
  await page.getByLabel('报告格式').selectOption('json');
  const interimDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: '导出阶段报告', exact: true }).click();
  await page.getByRole('button', { name: '下载文件', exact: true }).click();
  const interim = JSON.parse(await readFile((await (await interimDownload).path())!, 'utf8'));
  expect(interim.interim).toBe(true);
  expect(interim.snapshot_state).toBe('RUNNING');
  await page.goto('/#/environment');
  await page.getByRole('button', { name: '编辑模型连接', exact: true }).click();
  await expect(page.getByRole('button', { name: '保存配置', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: '取消编辑' }).click();
  const release = await page.request.post(new URL('/__test__/release-auditors', endpoint!).toString());
  expect(release.ok()).toBe(true);
  await page.goto(runUrl);
  await expect(page.locator('.run-status')).toHaveText('分析完成', { timeout: 60_000 });
  await expect(page.locator('.workflow-progress li.complete')).toHaveCount(5);
  await page.getByRole('tab', { name: '报告历史', exact: true }).click();
  await expect(page.locator('.report-history tbody tr')).toContainText('阶段报告');
  await expect(page.locator('.report-history tbody tr')).toContainText('执行中');

  await page.getByRole('tab', { name: /^漏洞审计/ }).click();
  await page.getByRole('tab', { name: '复核总览', exact: true }).click();
  await expect(page.getByRole('region', { name: '复核总览' })).toContainText('尚无人工复核记录：1 项');
  await page.getByRole('button', { name: '查看并复核', exact: true }).click();
  await page.getByText('提交人工复核', { exact: true }).click();
  const stalePage = await page.context().newPage();
  stalePage.on('response', (response) => {
    if (response.status() === 403 && response.url().includes('/rpc/')) forbidden.push(response.url());
  });
  await stalePage.route('**/api/session', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 350));
    await route.continue();
  });
  await stalePage.goto(runUrl);
  await stalePage.getByText('提交人工复核', { exact: true }).click();
  await stalePage
    .getByRole('textbox', { name: '复核说明', exact: true })
    .fill('旧窗口草稿，不能覆盖其他窗口的修订');
  await page.getByRole('combobox', { name: '结论', exact: true }).selectOption('INCONCLUSIVE');
  await page.getByRole('textbox', { name: '复核说明', exact: true }).fill('人工复核：需要检查上游入口');
  await page.getByRole('textbox', { name: '反证与防护', exact: true }).fill('反证标记：上游可能限制了目录');
  await page
    .getByRole('textbox', { name: '待补信息', exact: true })
    .fill('补充标记：需要路由配置与调用者代码');
  await page.getByRole('button', { name: '保存修订', exact: true }).click();
  await expect(page.locator('.review-card').last()).toContainText('反证标记');
  await expect(page.locator('.review-card').last()).toContainText('补充标记');
  await stalePage.getByRole('button', { name: '保存修订', exact: true }).click();
  await expect(stalePage.locator('.audit-workspace .error-banner')).toContainText('发现已更新');
  await expect(stalePage.locator('.global-error')).toHaveCount(0);
  await expect(stalePage.getByRole('textbox', { name: '复核说明', exact: true })).toHaveValue(
    '旧窗口草稿，不能覆盖其他窗口的修订',
  );
  await stalePage.close();
  await page.reload();
  await expect(page.locator('.review-card').last()).toContainText('反证标记');
  await page.getByLabel('报告格式').selectOption('json');
  const finalDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: '导出报告', exact: true }).click();
  await page.getByRole('button', { name: '下载文件', exact: true }).click();
  const finalReport = JSON.parse(await readFile((await (await finalDownload).path())!, 'utf8'));
  expect(finalReport.interim).toBe(false);
  const humanReview = finalReport.audit.reviews.find((review: { actor: string }) => review.actor === 'HUMAN');
  expect(humanReview.draft.counter_evidence).toBe('反证标记：上游可能限制了目录');
  expect(humanReview.draft.missing_information).toBe('补充标记：需要路由配置与调用者代码');
  await page.getByRole('tab', { name: '报告历史', exact: true }).click();
  await expect(page.locator('.report-history tbody tr')).toHaveCount(2);
  const historicalDownload = page.waitForEvent('download');
  await page
    .locator('.report-history tbody tr')
    .filter({ hasText: '阶段报告' })
    .getByRole('button', { name: '下载报告' })
    .click();
  await page.getByRole('button', { name: '下载文件', exact: true }).click();
  expect(JSON.parse(await readFile((await (await historicalDownload).path())!, 'utf8'))).toEqual(interim);
  await expect(page.locator('.toast')).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('immutable-report-history.png'), fullPage: true });
  await page.getByRole('tab', { name: /^漏洞审计/ }).click();
  await page.getByRole('tab', { name: '复核总览', exact: true }).click();
  await expect(page.getByRole('region', { name: '复核总览' })).toContainText('尚无人工复核记录：0 项');
  await expect(page.locator('.review-overview tbody tr')).toContainText('补充标记');
  await page.screenshot({ path: testInfo.outputPath('review-overview.png'), fullPage: true });
  await page.getByRole('tab', { name: '智能体记录', exact: true }).click();
  const requestDownload = page.waitForEvent('download');
  await page.locator('.agent-records').getByRole('link', { name: '请求', exact: true }).first().click();
  await page.getByRole('button', { name: '下载文件', exact: true }).click();
  const request = await readFile((await (await requestDownload).path())!, 'utf8');
  expect(request).toContain('人工上下文标记');
  expect(request).not.toContain('browser-fixture-key');
  await page.getByRole('tab', { name: '任务事件', exact: false }).click();
  await expect(page.locator('.event-list')).toContainText('阶段 3/5');
  await page.getByRole('tab', { name: /^漏洞审计/ }).click();
  await page.screenshot({ path: testInfo.outputPath('capability-audit.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: testInfo.outputPath('capability-mobile.png'), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
  expect(forbidden).toEqual([]);
});

test('binary audit retains real recovery and displays the same typed plan with addresses', async ({
  page,
}, testInfo) => {
  test.setTimeout(180_000);
  const endpoint = process.env.AEGIS_E2E_MODEL_ENDPOINT;
  test.skip(!endpoint || process.env.AEGIS_SKIP_GHIDRA === '1', 'Requires the isolated provider and Ghidra');
  await page.goto('/#/environment');
  await page.getByRole('button', { name: /^(配置|编辑)模型连接$/ }).click();
  await page.getByLabel('接口类型').selectOption('OPENAI_COMPATIBLE');
  await page.getByLabel('API 基础地址').fill(endpoint!);
  await page.getByLabel('模型标识').fill('browser-fixture-model');
  await page.getByLabel('密钥处理').selectOption('REPLACE');
  await page.getByLabel('API Key', { exact: true }).fill('browser-fixture-key');
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(page.locator('.model-panel')).toContainText('网页保存（Windows 加密）');
  const release = await page.request.post(new URL('/__test__/release-auditors', endpoint!).toString());
  expect(release.ok()).toBe(true);
  await page.goto('/#/projects');
  await page.getByRole('button', { name: '导入新项目', exact: true }).click();
  await page.getByLabel('项目名称', { exact: true }).fill('二进制规划闭环验证');
  await page.getByRole('button', { name: 'PE / ELF', exact: true }).click();
  const fixture = await readFile(
    path.resolve(import.meta.dirname, '../../tests/fixtures/binary/sample-pe64.exe'),
  );
  await page
    .getByLabel('选择二进制文件')
    .setInputFiles({ name: 'binary-plan.exe', mimeType: 'application/octet-stream', buffer: fixture });
  await page.getByRole('button', { name: '导入并创建快照', exact: true }).click();
  const card = page.locator('.snapshot-card').filter({ hasText: 'binary-plan.exe' });
  await expect(card.getByText('可分析', { exact: true })).toBeVisible();
  await card.getByRole('button', { name: '开始漏洞审计', exact: true }).click();
  await page.getByRole('button', { name: '开始审计', exact: true }).click();
  await expect(page.locator('.run-status')).toHaveText('分析完成', { timeout: 120_000 });
  await expect(page.locator('.workflow-progress li')).toHaveCount(6);
  const plan = page.getByRole('region', { name: '顶层审计规划' });
  await expect(plan).toContainText('先按函数地址核对入口');
  await expect(plan).toContainText('从实际恢复的第一个函数');
  await expect(plan.locator('small')).toContainText('0x');
  await page.screenshot({ path: testInfo.outputPath('binary-audit-plan.png'), fullPage: true });
  await page.locator('.workflow-progress li').filter({ hasText: '逆向与反编译' }).getByRole('button').click();
  await expect(page.locator('.recovery-panel')).toContainText('Ghidra 反编译');
  await expect(page.locator('.recovery-panel')).toContainText('工具已完成');
  await page.screenshot({ path: testInfo.outputPath('binary-recovery.png'), fullPage: true });
  await page.reload();
  await expect(page.getByRole('region', { name: '顶层审计规划' })).toContainText('先按函数地址核对入口');
});

test('environment credentials remain a visible fallback and cannot follow an endpoint change', async ({
  page,
}, testInfo) => {
  const base = process.env.AEGIS_E2E_ENV_BASE_URL;
  test.skip(!base, 'Requires the isolated environment-configured server');
  await page.goto(base! + '/#/environment');
  const panel = page.locator('.model-panel');
  await expect(panel).toContainText('环境变量 AEGIS_MODEL_API_KEY');
  await expect(panel).toContainText('environment-fixture-model');
  await page.getByRole('button', { name: '编辑模型连接', exact: true }).click();
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(panel).toContainText('连接设置已保存');
  await expect(panel).toContainText('环境变量 AEGIS_MODEL_API_KEY');
  await page.getByRole('button', { name: '检测连接', exact: true }).click();
  await expect(panel).toContainText('调用已验证');
  await page.screenshot({ path: testInfo.outputPath('environment-key-source.png'), fullPage: true });
  await page.getByRole('button', { name: '编辑模型连接', exact: true }).click();
  await page.getByLabel('API 基础地址').fill('http://127.0.0.1:1/v1');
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(panel.getByRole('alert')).toContainText('重新填写该接口的密钥');
  await page.getByLabel('密钥处理').selectOption('CLEAR');
  await page.getByRole('button', { name: '保存配置', exact: true }).click();
  await expect(panel).toContainText('凭据来源：未配置');
  await expect(page.getByRole('button', { name: '检测连接', exact: true })).toBeDisabled();
  await page.reload();
  await expect(panel).toContainText('http://127.0.0.1:1/v1');
  await expect(panel).toContainText('凭据来源：未配置');
});
