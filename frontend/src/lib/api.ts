import { createClient, ConnectError, type Interceptor } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import {
  ProjectService,
  RunService,
  ProgramService,
  ReportService,
  SystemService,
  FindingService,
  RuntimeService,
} from '../gen/audit/v1/audit_pb';

let csrf = '';
let establishing: Promise<void> | undefined;
export function establishSession(): Promise<void> {
  if (!establishing) {
    establishing = (async () => {
      const response = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('无法建立本机会话，请检查控制服务。');
      const session: { csrf_token: string } = await response.json();
      if (!session.csrf_token) throw new Error('本机会话响应无效，请重新连接控制服务。');
      csrf = session.csrf_token;
    })().finally(() => {
      establishing = undefined;
    });
  }
  return establishing;
}
const sessionHeader: Interceptor = (next) => async (request) => {
  // Direct run links can mount children before App finishes its initial session.
  if (establishing || !csrf) await establishSession();
  request.header.set('x-aegis-csrf', csrf);
  return next(request);
};
const transport = createConnectTransport({
  baseUrl: '/rpc',
  defaultTimeoutMs: 15_000,
  interceptors: [sessionHeader],
});
export const projectsApi = createClient(ProjectService, transport);
export const runsApi = createClient(RunService, transport);
export const programsApi = createClient(ProgramService, transport);
export const reportsApi = createClient(ReportService, transport);
export const systemApi = createClient(SystemService, transport);
export const findingsApi = createClient(FindingService, transport);
export const runtimeApi = createClient(RuntimeService, transport);
export const requestId = () => crypto.randomUUID();
export const artifactUrl = (id: string) => `/api/artifacts/${encodeURIComponent(id)}`;

export function errorMessage(error: unknown): string {
  return error instanceof ConnectError
    ? error.rawMessage
    : error instanceof Error
      ? error.message
      : String(error);
}
export async function upload(
  file: Blob,
  name: string,
  onProgress: (percent: number) => void,
): Promise<string> {
  if (file.size > 512 * 1024 * 1024) throw new Error('单次上传上限为 512 MiB。');
  if (establishing || !csrf) await establishSession();
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open(
      'POST',
      '/api/uploads?' + new URLSearchParams({ name, media_type: file.type || 'application/octet-stream' }),
    );
    request.setRequestHeader('x-aegis-csrf', csrf);
    request.timeout = 300_000;
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error('上传连接中断，请检查控制服务。'));
    request.ontimeout = () => reject(new Error('上传超时，请重试。'));
    request.onload = () => {
      try {
        const result = JSON.parse(request.responseText);
        if (request.status >= 200 && request.status < 300) resolve(result.id);
        else reject(new Error(result.message || `上传失败 (${request.status})`));
      } catch {
        reject(new Error('上传服务返回了无效响应。'));
      }
    };
    request.send(file);
  });
}
