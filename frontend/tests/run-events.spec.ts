import { expect, test, type Page } from '@playwright/test';
import { RunState } from '../src/gen/audit/v1/audit_pb';

type EventData = {
  runId: string;
  seq: string;
  createdAt: string;
  kind: string;
  message: string;
  phaseId: string;
  phaseOrder: number;
  phaseCount: number;
  current: string;
  total: string;
};

declare global {
  interface Window {
    taskEventStream: {
      requests: { afterSeq?: string }[];
      push: (events: EventData[]) => void;
      disconnect: () => void;
      finish: () => void;
    };
  }
}

const event = (seq: number, message = `正在分析函数 ${seq} 的调用关系`): EventData => ({
  runId: 'events-run',
  seq: String(seq),
  createdAt: new Date(Date.UTC(2026, 8, 12, 2, 0, seq)).toISOString(),
  kind: 'TOOL_PROGRESS',
  message,
  phaseId: 'STRUCTURE',
  phaseOrder: 2,
  phaseCount: 5,
  current: String(seq),
  total: '600',
});

async function workspace(page: Page, scope = 'STRUCTURE_ANALYSIS', runState = RunState.RUNNING) {
  const snapshot = {
    id: 'events-snapshot',
    projectId: 'events-project',
    name: 'analysis-demo.zip',
    kind: 1,
    state: 2,
    createdAt: '2026-09-12T02:00:00Z',
    fileCount: '12',
    totalBytes: '1024',
  };
  const run = {
    id: 'events-run',
    projectId: snapshot.projectId,
    snapshotId: snapshot.id,
    scope,
    state: runState,
    createdAt: snapshot.createdAt,
    unitCount: '0',
    summaryJson: '{}',
  };
  await page.route('**/api/session', (route) => route.fulfill({ json: { csrf_token: 'events-fixture' } }));
  await page.route('**/rpc/**', (route) => {
    const method = route.request().url().split('/').pop();
    const responses: Record<string, unknown> = {
      ListProjects: {
        projects: [{ id: snapshot.projectId, name: '实时分析演示', createdAt: snapshot.createdAt }],
      },
      GetProject: { snapshots: [snapshot] },
      GetSnapshot: { snapshot },
      GetAudit:
        scope === 'SECURITY_AUDIT'
          ? {
              tasks: [
                {
                  id: 'events-plan',
                  runId: run.id,
                  itemKey: 'events-finding',
                  role: 'VERIFIER',
                  status: 'SUCCEEDED',
                  resultJson: JSON.stringify({
                    status: 'UNSUPPORTED',
                    rationale: '事件测试中的已保存方案',
                    limitations: [],
                    config: null,
                  }),
                },
              ],
            }
          : {},
      ListRuns: { runs: [run] },
      GetRun: {
        run,
        phases: [
          { id: 'PREPARATION', title: '任务准备', order: 1, status: 'COMPLETED' },
          {
            id: 'STRUCTURE',
            title: '程序结构解析',
            order: 2,
            status: run.state === RunState.RUNNING ? 'RUNNING' : 'COMPLETED',
            detail: '正在建立函数索引并梳理调用关系',
            current: '3',
            total: '12',
          },
        ],
      },
      GetCapabilities: { version: '0.2.0', executors: [] },
    };
    return route.fulfill({ json: responses[method || ''] || {} });
  });
  // Keep a real ReadableStream open so events arrive separately through Connect's
  // framing/parser, without a running executor or changes to the local database.
  await page.addInitScript(() => {
    const originalFetch = window.fetch.bind(window);
    let streamController: ReadableStreamDefaultController<Uint8Array>;
    function frame(value: unknown, flags = 0) {
      const json = new TextEncoder().encode(JSON.stringify(value));
      const bytes = new Uint8Array(json.length + 5);
      bytes[0] = flags;
      new DataView(bytes.buffer).setUint32(1, json.length);
      bytes.set(json, 5);
      return bytes;
    }
    window.taskEventStream = {
      requests: [],
      push: (events) => {
        for (const event of events) streamController.enqueue(frame({ event }));
      },
      disconnect: () => streamController.error(new TypeError('fixture connection interrupted')),
      finish: () => {
        streamController.enqueue(frame({}, 2));
        streamController.close();
      },
    };
    window.fetch = async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (!url.endsWith('/audit.v1.RunService/WatchRun')) return originalFetch(input, init);
      const request = JSON.parse(new TextDecoder().decode((init!.body as Uint8Array).subarray(5)));
      window.taskEventStream.requests.push(request);
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            streamController = controller;
            init?.signal?.addEventListener(
              'abort',
              () => controller.error(new DOMException('Aborted', 'AbortError')),
              {
                once: true,
              },
            );
          },
        }),
        { headers: { 'content-type': 'application/connect+json' } },
      );
    };
  });
  await page.goto('/#/runs/events-run');
  await expect.poll(() => page.evaluate(() => window.taskEventStream.requests.length)).toBe(1);
  await expect(page.locator('.run-status')).toBeVisible();
  return run;
}

async function push(page: Page, events: EventData[]) {
  await page.evaluate((events) => window.taskEventStream.push(events), events);
}

test('only the events tab shows the log and receives incoming events in reverse order', async ({
  page,
}, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const run = await workspace(page, 'SECURITY_AUDIT');
  run.summaryJson = JSON.stringify({
    recovery: {
      status: 'PLANNED',
      plan: { assessment: '已建立逆向分析方案', evidence: [], steps: [], limitations: [] },
    },
  });
  await expect(page.locator('.events-panel')).toHaveCount(0);
  await push(page, [event(1, '已连接执行器，开始分析'), event(2), event(3)]);
  await push(page, [event(4, '已提取函数入口，正在检查调用路径')]);

  for (const name of ['运行验证', '报告历史', '关键逻辑', '逆向与解混淆', '覆盖与产物', '程序视图']) {
    await page.getByRole('tab', { name, exact: true }).click();
    await expect(page.locator('.events-panel')).toHaveCount(0);
  }
  await page.getByRole('tab', { name: /^漏洞审计/ }).click();
  await expect(page.locator('.events-panel')).toHaveCount(0);
  await page.getByRole('tab', { name: /^任务事件/ }).click();
  await expect(page.locator('.events-panel')).toHaveCount(1);
  const log = page.getByRole('log', { name: '任务事件列表', exact: true });
  await expect(log.locator('.event-seq')).toHaveText(['004', '003', '002', '001']);
  await push(page, [event(5, '新事件到达：正在交叉检查调用参数')]);
  await expect(log.locator('.event-row').first()).toContainText('新事件到达');
  expect(
    await log
      .locator('.event-row')
      .first()
      .evaluate((row) => row.getAnimations().length),
  ).toBeGreaterThan(0);
  await expect.poll(() => log.evaluate((node) => node.scrollTop)).toBe(0);
  await page.screenshot({ path: testInfo.outputPath('events-live-desktop.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('stream reconnect resumes from the cursor without duplicates and archives on completion', async ({
  page,
}) => {
  const run = await workspace(page);
  await push(page, [event(1), event(2)]);
  await page.getByRole('tab', { name: /^任务事件/ }).click();
  await expect(page.locator('.event-seq')).toHaveText(['002', '001']);
  await page.evaluate(() => window.taskEventStream.disconnect());
  await expect(page.locator('.event-connection')).toContainText('连接中断');
  await expect(page.locator('.event-connection.live')).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => window.taskEventStream.requests.length)).toBe(2);
  expect(await page.evaluate(() => window.taskEventStream.requests[1].afterSeq)).toBe('2');
  await push(page, [event(2), event(3)]);
  await expect(page.locator('.event-seq')).toHaveText(['003', '002', '001']);
  run.state = RunState.COMPLETED;
  const completed = { ...event(4, '分析已完成'), kind: 'RUN_COMPLETED' };
  await push(page, [completed]);
  await page.evaluate(() => window.taskEventStream.finish());
  await expect(page.locator('.event-connection')).toHaveText('事件已归档');
  await expect(page.locator('.activity-dot')).toHaveCount(0);
  await expect(page.locator('.event-seq')).toHaveText(['004', '003', '002', '001']);
  await page.getByRole('tab', { name: '程序视图', exact: true }).click();
  await expect(page.locator('.events-panel')).toHaveCount(0);
  await page.reload();
  await expect.poll(() => page.evaluate(() => window.taskEventStream.requests.length)).toBe(1);
  await push(page, [event(1), event(2), event(3), completed]);
  await page.evaluate(() => window.taskEventStream.finish());
  await page.getByRole('tab', { name: /^任务事件/ }).click();
  await expect(page.locator('.event-seq')).toHaveText(['004', '003', '002', '001']);
  await expect(page.locator('.event-connection')).toHaveText('事件已归档');
});

test('reading history preserves position, offers new events and respects reduced motion on mobile', async ({
  page,
}, testInfo) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setViewportSize({ width: 390, height: 844 });
  await workspace(page);
  await push(
    page,
    Array.from({ length: 40 }, (_, index) => event(index + 1)),
  );
  await page.getByRole('tab', { name: /^任务事件/ }).click();
  const log = page.getByRole('log', { name: '任务事件列表', exact: true });
  await expect(log.locator('.event-row')).toHaveCount(40);
  await log.evaluate((node) => (node.scrollTop = 420));
  await expect(page.getByRole('button', { name: '回到最新', exact: true })).toBeVisible();
  const anchor = await log.evaluate((node) => {
    const top = node.getBoundingClientRect().top;
    const row = Array.from(node.children).find((row) => row.getBoundingClientRect().bottom > top)!;
    return { seq: row.getAttribute('data-seq'), offset: row.getBoundingClientRect().top - top };
  });
  await push(page, [
    event(
      41,
      '正在检查较长路径 src/components/analysis/validation/entry-point-with-long-name.ts\n分析继续运行，历史阅读位置保持不变。',
    ),
  ]);
  await expect(page.getByRole('button', { name: '1 条新事件', exact: true })).toBeVisible();
  const offset = await log
    .locator(`[data-seq="${anchor.seq}"]`)
    .evaluate((row) => row.getBoundingClientRect().top - row.parentElement!.getBoundingClientRect().top);
  expect(Math.abs(offset - anchor.offset)).toBeLessThan(2);
  await page.getByRole('button', { name: '1 条新事件', exact: true }).click();
  await expect.poll(() => log.evaluate((node) => node.scrollTop)).toBe(0);
  await expect(log.locator('.event-row').first()).toContainText('较长路径');
  expect(
    await log
      .locator('.event-row')
      .first()
      .evaluate((row) => row.getAnimations().length),
  ).toBe(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await log.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('events-mobile.png'), fullPage: true });
});

test('archived replay retains the latest 500 events in descending sequence order', async ({ page }) => {
  await workspace(page, 'STRUCTURE_ANALYSIS', RunState.COMPLETED);
  await push(
    page,
    Array.from({ length: 505 }, (_, index) => event(index + 1)),
  );
  await page.evaluate(() => window.taskEventStream.finish());
  await page.getByRole('tab', { name: /^任务事件/ }).click();
  await expect(page.locator('.event-row')).toHaveCount(500);
  await expect(page.locator('.event-seq').first()).toHaveText('505');
  await expect(page.locator('.event-seq').last()).toHaveText('006');
  await expect(page.locator('.event-connection')).toHaveText('事件已归档');
  expect(
    await page
      .locator('.event-row')
      .first()
      .evaluate((row) => row.getAnimations().length),
  ).toBe(0);
});
