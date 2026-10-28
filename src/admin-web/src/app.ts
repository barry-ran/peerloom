type Language = 'zh' | 'en';
type Resource = 'applications' | 'devices' | 'connection-grants' | 'sessions' | 'audit-events' | 'relay-nodes';
type Row = Record<string, unknown>;
type Session = { tenant_id: string; user_id: string; username: string; scope: 'read' | 'admin'; csrf_token: string; expires_at: string };
const words = {
  zh: { 'relay-nodes': '中继节点', region: '区域', endpoint: 'TURN 地址', secretRef: '运维批准的秘密引用', createRelay: '创建中继节点', relayNote: '只能引用运维预先批准的租户、地址与秘密绑定；不要输入共享秘密明文。', edit: '编辑', connectable: '允许新连接', tags: '标签（JSON 对象）', metadata: '元数据（JSON 对象）', invalidJSON: '请输入有效 JSON 对象', brand: '设备连接管理', login: '登录管理控制台', tenant: '租户 ID', user: '用户名', password: '密码', signIn: '安全登录', signOut: '退出登录', readOnly: '只读权限', admin: '管理员', applications: '应用', devices: '设备', 'connection-grants': '连接授权', sessions: '会话', 'audit-events': '审计', refresh: '刷新', next: '下一页', first: '回到第一页', loading: '正在加载…', empty: '这里还没有记录', createApp: '创建应用', grant: '签发连接授权', name: '名称', source: '源设备 ID', target: '目标设备 ID', expiry: '到期时间', save: '确认', cancel: '取消', close: '关闭', required: '请输入完整信息', error: '操作未完成', retry: '使用相同请求重试', uncertain: '结果尚未确认。请保留本页并重试相同请求，不要重复创建。', approve: '连接需要目标确认', max: '连接上限', enable: '启用', disable: '停用', revoke: '撤销', terminate: '结束会话', registration: '注册 grant', secret: '一次性注册凭证', secretNote: '仅交给可信业务后端。关闭后从本页移除，不写入浏览器存储。', copy: '复制', copied: '已复制', copyFail: '无法访问剪贴板，请手动选择复制', confirm: '确认变更', confirmNote: '这会影响目标资源。撤销不能撤回，已有连接仍受服务端通知及 SDK 授权租约约束。', appFilter: '应用 ID（可选）', online: '在线状态', all: '全部', yes: '在线', no: '离线', filter: '应用筛选', id: '标识', status: '状态', actions: '操作', readonlyNote: '当前账户只能查询，变更由服务端拒绝。', sessionNote: '浏览器只持安全会话；服务端凭证不会传入网页。', loginNote: '账户由数据库运维者显式创建。没有默认密码，也不能使用设备或服务端密钥登录。', back: '返回', approval: '需要确认', currentTenant: '当前租户', actor: '操作者', action: '事件', date: '时间', details: '详情', connected: '已连接', connecting: '连接中', authorizing: '待确认', closed: '已关闭', requested: '已请求', reconnecting: '重连中', active: '有效', revoked: '已撤销', unknown: '未知', disabled: '已停用' },
  en: { 'relay-nodes': 'Relay nodes', region: 'Region', endpoint: 'TURN URL', secretRef: 'Operator-approved secret reference', createRelay: 'Create relay node', relayNote: 'Only operator-approved tenant, URL and secret bindings are accepted. Never enter a shared secret here.', edit: 'Edit', connectable: 'Allow new connections', tags: 'Tags (JSON object)', metadata: 'Metadata (JSON object)', invalidJSON: 'Enter a valid JSON object', brand: 'Device connection console', login: 'Sign in to the console', tenant: 'Tenant ID', user: 'Username', password: 'Password', signIn: 'Sign in securely', signOut: 'Sign out', readOnly: 'Read only', admin: 'Administrator', applications: 'Applications', devices: 'Devices', 'connection-grants': 'Connection grants', sessions: 'Sessions', 'audit-events': 'Audit', refresh: 'Refresh', next: 'Next page', first: 'First page', loading: 'Loading…', empty: 'No records yet', createApp: 'Create application', grant: 'Issue connection grant', name: 'Name', source: 'Source device ID', target: 'Target device ID', expiry: 'Expires at', save: 'Confirm', cancel: 'Cancel', close: 'Close', required: 'Complete the required fields', error: 'The operation did not complete', retry: 'Retry the same request', uncertain: 'The outcome is not confirmed. Keep this page open and retry the same request; do not create a duplicate.', approve: 'Require target approval', max: 'Connection limit', enable: 'Enable', disable: 'Disable', revoke: 'Revoke', terminate: 'Terminate session', registration: 'Registration grant', secret: 'One-time registration grant', secretNote: 'Share only through a trusted business backend. Closing removes it from this page; it is never saved to browser storage.', copy: 'Copy', copied: 'Copied', copyFail: 'Clipboard unavailable. Select and copy manually.', confirm: 'Confirm change', confirmNote: 'This affects the selected resource. Revocation cannot be undone; existing connections are bounded by notifications and SDK authorization leases.', appFilter: 'Application ID (optional)', online: 'Online status', all: 'All', yes: 'Online', no: 'Offline', filter: 'Apply filters', id: 'Identifier', status: 'Status', actions: 'Actions', readonlyNote: 'This account can query only. The server rejects mutations.', sessionNote: 'The browser holds only a secure session. Service credentials never enter this page.', loginNote: 'An operator must explicitly create your account. There is no default password; device and service keys cannot sign in.', back: 'Back', approval: 'Approval required', currentTenant: 'Current tenant', actor: 'Actor', action: 'Event', date: 'Time', details: 'Details', connected: 'Connected', connecting: 'Connecting', authorizing: 'Awaiting approval', closed: 'Closed', requested: 'Requested', reconnecting: 'Reconnecting', active: 'Active', revoked: 'Revoked', unknown: 'Unknown', disabled: 'Disabled' }
};
type Word = keyof typeof words.zh;
let language: Language = localStorage.getItem('peerloom.language') === 'en' ? 'en' : 'zh';
const t = (key: Word): string => words[language][key];
let session: Session | null = null;
let resource: Resource = 'applications';
let cursor = '', nextCursor = '', appFilter = '', onlineFilter = '';
let generation = 0;
let authEpoch = 0;
let busyMutation = false;
let uncertainMutation = false;
window.addEventListener('beforeunload', event => { if (busyMutation || uncertainMutation) { event.preventDefault(); event.returnValue = ''; } });
const root = document.querySelector<HTMLDivElement>('#app')!;
const el = <K extends keyof HTMLElementTagNameMap>(tag: K, className = '', text = ''): HTMLElementTagNameMap[K] => {
  const element = document.createElement(tag); element.className = className; element.textContent = text; return element;
};
const button = (label: string, action: () => void, className = 'button'): HTMLButtonElement => {
  const element = el('button', className, label); element.type = 'button'; element.addEventListener('click', action); return element;
};
class APIError extends Error { constructor(public status: number, public code: string) { super(code); } }
async function api(path: string, method = 'GET', data?: unknown, key?: string): Promise<Row> {
  const epoch = authEpoch;
  const abort = new AbortController(); const timer = setTimeout(() => abort.abort(), 10_000);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && session) headers['X-CSRF-Token'] = session.csrf_token;
  if (key) headers['Idempotency-Key'] = key;
  try {
    const response = await fetch(`/admin/api${path}`, { method, headers, ...(data !== undefined ? { body: JSON.stringify(data) } : {}), credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: abort.signal });
    const reader = response.body?.getReader(); if (!reader) throw new APIError(502, 'INVALID_RESPONSE');
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > 1_048_576) { await reader.cancel(); throw new APIError(502, 'RESPONSE_TOO_LARGE'); } chunks.push(part.value); }
    const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const text = new TextDecoder().decode(bytes);
    let payload: Row; try { payload = JSON.parse(text) as Row; } catch { throw new APIError(502, 'INVALID_RESPONSE'); }
    if (!response.ok) { if (response.status === 401 && session && epoch === authEpoch) { session = null; authEpoch++; generation++; busyMutation = false; renderLogin(); } throw new APIError(response.status, typeof payload['code'] === 'string' ? payload['code'] : 'REQUEST_FAILED'); }
    if (epoch !== authEpoch) throw new APIError(409, 'STALE_SESSION');
    return payload;
  } finally { clearTimeout(timer); }
}
function languageButton(): HTMLButtonElement {
  return button(language === 'zh' ? 'English' : '中文', () => { if (busyMutation) return; language = language === 'zh' ? 'en' : 'zh'; localStorage.setItem('peerloom.language', language); document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en'; session ? renderShell() : renderLogin(); }, 'button quiet');
}
function field(label: string, type = 'text', value = ''): [HTMLLabelElement, HTMLInputElement] {
  const wrap = el('label', 'field'); wrap.append(el('span', '', label)); const input = el('input'); input.type = type; input.value = value; input.required = true; wrap.append(input); return [wrap, input];
}
function message(container: HTMLElement, error: unknown): void {
  const note = el('div', 'notice error', `${t('error')} · ${error instanceof APIError ? error.code : 'NETWORK_UNAVAILABLE'}`); note.setAttribute('role', 'alert'); container.replaceChildren(note);
}
function renderLogin(): void {
  root.replaceChildren(); const page = el('main', 'login-page'); const card = el('section', 'login-card');
  const top = el('div', 'row between'); top.append(el('div', 'brand', 'Peerloom'), languageButton());
  card.append(top, el('p', 'eyebrow', t('brand')), el('h1', '', t('login')), el('p', 'muted', t('loginNote')));
  const form = el('form'); const [tenantWrap, tenant] = field(t('tenant')); tenant.autocomplete = 'organization'; tenant.name = 'tenant';
  const [userWrap, user] = field(t('user')); user.autocomplete = 'username'; user.name = 'username';
  const [passwordWrap, password] = field(t('password'), 'password'); password.autocomplete = 'current-password'; password.name = 'password'; password.maxLength = 1024;
  const submit = el('button', 'button primary', t('signIn')); submit.type = 'submit'; const error = el('div');
  form.append(tenantWrap, userWrap, passwordWrap, error, submit);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (submit.disabled || !form.reportValidity()) return; submit.disabled = true; error.replaceChildren();
    const data = { tenant_id: tenant.value.trim(), username: user.value.trim(), password: password.value }; password.value = '';
    try { session = await api('/auth/login', 'POST', data) as Session; authEpoch++; cursor = ''; renderShell(); } catch (failure) { message(error, failure); } finally { submit.disabled = false; }
  });
  card.append(form, el('p', 'fine', t('sessionNote'))); page.append(card); root.append(page);
}
function renderShell(): void {
  if (!session) { renderLogin(); return; }
  generation++; root.replaceChildren(); const layout = el('div', 'layout'); const aside = el('aside', 'sidebar');
  aside.append(el('div', 'brand', 'Peerloom'), el('p', 'sidebar-subtitle', t('brand')));
  const navigation = el('nav'); navigation.setAttribute('aria-label', t('brand'));
  for (const name of ['applications', 'devices', 'connection-grants', 'sessions', 'relay-nodes', 'audit-events'] as Resource[]) {
    const item = button(t(name), () => { if (busyMutation) return; resource = name; cursor = ''; renderShell(); }, `nav-item ${resource === name ? 'selected' : ''}`);
    if (resource === name) item.setAttribute('aria-current', 'page'); navigation.append(item);
  }
  aside.append(navigation); const identity = el('div', 'identity'); identity.append(el('strong', '', session.username), el('span', '', session.scope === 'admin' ? t('admin') : t('readOnly'))); aside.append(identity);
  const main = el('main', 'workspace'); const header = el('header', 'header'); const title = el('div'); title.append(el('p', 'eyebrow', t('currentTenant')), el('span', 'tenant-id', session.tenant_id));
  const controls = el('div', 'row'); controls.append(languageButton(), button(t('signOut'), async () => {
    if (busyMutation) return;
    try { await api('/auth/logout', 'POST', {}); session = null; authEpoch++; generation++; renderLogin(); } catch (error) { showGlobalError(error); }
  })); header.append(title, controls); main.append(header);
  const heading = el('div', 'row between page-heading'); heading.append(el('h1', '', t(resource))); const actions = el('div', 'row');
  actions.append(button(t('refresh'), () => { if (!busyMutation) void loadRows(); }));
  if (session.scope === 'admin' && resource === 'applications') actions.append(button(t('createApp'), createApplication, 'button primary'));
  if (session.scope === 'admin' && resource === 'connection-grants') actions.append(button(t('grant'), createGrant, 'button primary'));
  if (session.scope === 'admin' && resource === 'relay-nodes') actions.append(button(t('createRelay'), () => editRelay(), 'button primary'));
  heading.append(actions); main.append(heading);
  if (session.scope === 'read') main.append(el('p', 'notice', t('readonlyNote')));
  const feedback = el('div'); feedback.id = 'feedback'; main.append(feedback);
  if (resource === 'devices') {
    const filters = el('form', 'filters'); const [appWrap, app] = field(t('appFilter'), 'text', appFilter); app.required = false;
    const onlineWrap = el('label', 'field'); onlineWrap.append(el('span', '', t('online'))); const online = el('select');
    for (const [value, label] of [['', t('all')], ['true', t('yes')], ['false', t('no')]]) { const option = el('option', '', label!); option.value = value!; option.selected = value === onlineFilter; online.append(option); } onlineWrap.append(online);
    const apply = el('button', 'button', t('filter')); apply.type = 'submit'; filters.append(appWrap, onlineWrap, apply);
    filters.addEventListener('submit', event => { event.preventDefault(); if (busyMutation) return; appFilter = app.value.trim(); onlineFilter = online.value; cursor = ''; void loadRows(); }); main.append(filters);
  }
  const tableArea = el('section', 'table-panel'); tableArea.id = 'table-area'; tableArea.setAttribute('aria-live', 'polite'); tableArea.setAttribute('aria-label', t(resource)); tableArea.tabIndex = 0; main.append(tableArea);
  const paging = el('div', 'row pagination'); paging.append(button(t('first'), () => { if (!busyMutation) { cursor = ''; void loadRows(); } }), button(t('next'), () => { if (!busyMutation && nextCursor) { cursor = nextCursor; void loadRows(); } })); paging.lastElementChild!.id = 'next-page'; main.append(paging);
  layout.append(aside, main); root.append(layout); void loadRows();
}
function showGlobalError(error: unknown): void { const container = document.querySelector<HTMLElement>('#feedback'); if (container) message(container, error); }
function text(value: unknown): string { return value == null ? '—' : typeof value === 'object' ? JSON.stringify(value) : String(value); }
function translatedStatus(value: unknown): string { const code = text(value); return code in words[language] ? t(code as Word) : code; }
async function loadRows(): Promise<void> {
  const ticket = ++generation; const area = document.querySelector<HTMLElement>('#table-area'); if (!area) return;
  nextCursor = ''; const nextButton = document.querySelector<HTMLButtonElement>('#next-page'); if (nextButton) nextButton.disabled = true;
  area.replaceChildren(el('p', 'empty', t('loading'))); const query = new URLSearchParams({ limit: '50' }); if (cursor) query.set('cursor', cursor);
  if (resource === 'devices') { if (appFilter) query.set('application_id', appFilter); if (onlineFilter) query.set('online', onlineFilter); }
  try {
    const data = await api(`/v1/${resource}?${query}`); if (ticket !== generation) return;
    if (!Array.isArray(data['items'])) throw new APIError(502, 'INVALID_RESPONSE');
    nextCursor = typeof data['next_cursor'] === 'string' ? data['next_cursor'] : ''; const next = document.querySelector<HTMLButtonElement>('#next-page'); if (next) next.disabled = !nextCursor;
    area.replaceChildren(); const rows = data['items'] as Row[];
    if (!rows.length) { area.append(el('p', 'empty', t('empty'))); return; }
    const columns: Array<[string, string]> = resource === 'applications' ? [['name', t('name')], ['id', t('id')], ['enabled', t('status')], ['require_target_approval', t('approval')]] : resource === 'devices' ? [['display_name', t('name')], ['id', t('id')], ['platform', 'Platform'], ['online', t('online')], ['status', t('status')]] : resource === 'connection-grants' ? [['source_device_id', t('source')], ['target_device_id', t('target')], ['expires_at', t('expiry')], ['revoked_at', t('revoke')]] : resource === 'sessions' ? [['id', t('id')], ['source_device_id', t('source')], ['target_device_id', t('target')], ['state', t('status')], ['close_reason', t('status')]] : resource === 'relay-nodes' ? [['name', t('name')], ['region', t('region')], ['endpoint', t('endpoint')], ['enabled', t('status')]] : [['id', t('id')], ['created_at', t('date')], ['actor_type', t('actor')], ['action', t('action')], ['resource_id', t('id')]];
    const table = el('table'); const head = el('thead'); const labels = el('tr'); for (const [, label] of columns) labels.append(el('th', '', label)); labels.append(el('th', '', t('actions'))); head.append(labels); table.append(head);
    const body = el('tbody');
    for (const row of rows) { const tr = el('tr'); for (const [key] of columns) { const td = el('td'); let content = text(row[key]); if (key === 'state' || key === 'status') content = translatedStatus(row[key]); if (typeof row[key] === 'boolean') content = row[key] ? '✓ true' : '— false'; if (key.endsWith('_at') && typeof row[key] === 'string') { const date = new Date(row[key] as string); if (!Number.isNaN(date.getTime())) content = date.toLocaleString(language === 'zh' ? 'zh-CN' : 'en'); } td.textContent = content; td.title = text(row[key]); if (key.endsWith('id')) td.className = 'identifier'; tr.append(td); } const controls = el('td', 'table-actions'); controls.append(button(t('details'), () => showDetails(row), 'button small')); addActions(controls, row); tr.append(controls); body.append(tr); }
    table.append(body); area.append(table);
  } catch (error) { if (ticket === generation) message(area, error); }
}
function modal(title: string, canDismiss: () => boolean = () => true): { dialog: HTMLDialogElement; content: HTMLDivElement; dismiss: () => void } {
  const previous = document.activeElement; const dialog = el('dialog', 'modal'); const heading = el('h2', '', title); const content = el('div');
  const dismiss = (): void => { if (busyMutation || !canDismiss()) return; dialog.close(); dialog.remove(); if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  const top = el('div', 'row between'); top.append(heading, button('×', dismiss, 'button quiet')); top.lastElementChild!.setAttribute('aria-label', t('close')); dialog.append(top, content);
  dialog.addEventListener('cancel', event => { event.preventDefault(); dismiss(); }); root.append(dialog); dialog.showModal(); return { dialog, content, dismiss };
}
function showDetails(row: Row): void { const view = modal(t('details')); view.content.append(el('pre', 'details', JSON.stringify(row, null, 2))); }
function mutate(title: string, method: string, path: string, input: Row, after?: (value: Row) => void): void {
  if (busyMutation) return; let unresolved = false; const view = modal(title, () => { if (unresolved && !window.confirm(t('uncertain'))) return false; uncertainMutation = false; return true; }); const status = el('div'); view.content.append(el('p', 'muted', t('confirmNote')), status);
  const key = crypto.randomUUID(); const confirm = button(t('save'), () => { void execute(); }, 'button primary'); view.content.append(confirm);
  const execute = async (): Promise<void> => {
    const epoch = authEpoch;
    if (busyMutation) return; busyMutation = true; confirm.disabled = true; status.replaceChildren(el('p', '', t('loading')));
    try { const result = await api(path, method, input, key); busyMutation = false; unresolved = false; uncertainMutation = false; view.dismiss(); await loadRows(); if (session && epoch === authEpoch) after?.(result); }
    catch (error) { busyMutation = false; confirm.disabled = false; message(status, error); if (!(error instanceof APIError) || error.status >= 500) { unresolved = true; uncertainMutation = true; status.append(el('p', 'muted', t('uncertain'))); confirm.textContent = t('retry'); } }
  };
}
function addActions(container: HTMLElement, row: Row): void {
  if (session?.scope !== 'admin') return; const id = text(row['id']);
  if (resource === 'applications') {
    container.append(button(t('edit'), () => editApplication(row), 'button small'));
    container.append(button(row['enabled'] ? t('disable') : t('enable'), () => mutate(t('confirm'), 'PATCH', `/v1/applications/${id}`, { enabled: !row['enabled'] }), 'button small'));
    container.append(button(t('registration'), () => mutate(t('registration'), 'POST', '/v1/registration-grants', { application_id: id, expires_in_seconds: 300 }, showRegistration), 'button small'));
  } else if (resource === 'devices' && row['status'] !== 'revoked') { container.append(button(t('edit'), () => editDevice(row), 'button small')); container.append(button(t('revoke'), () => mutate(t('confirm'), 'POST', `/v1/devices/${id}/revoke`, {}), 'button small danger')); }
  else if (resource === 'relay-nodes') { container.append(button(t('edit'), () => editRelay(row), 'button small')); container.append(button(row['enabled'] ? t('disable') : t('enable'), () => mutate(t('confirm'), 'PATCH', `/v1/relay-nodes/${id}`, {enabled: !row['enabled']}), 'button small')); }
  else if (resource === 'connection-grants' && !row['revoked_at']) container.append(button(t('revoke'), () => mutate(t('confirm'), 'DELETE', `/v1/connection-grants/${id}`, {}), 'button small danger'));
  else if (resource === 'sessions' && row['state'] !== 'closed') container.append(button(t('terminate'), () => mutate(t('confirm'), 'POST', `/v1/sessions/${id}/terminate`, {}), 'button small danger'));
}
function showRegistration(result: Row): void {
  const view = modal(t('secret')); const value = typeof result['grant'] === 'string' ? result['grant'] : '';
  if (!value) { view.content.append(el('p', 'notice error', 'INVALID_RESPONSE')); return; }
  const output = el('textarea', 'secret'); output.readOnly = true; output.value = value; output.setAttribute('aria-label', t('secret')); const note = el('p', 'muted', t('secretNote'));
  view.content.append(note, output, button(t('copy'), async () => { try { await navigator.clipboard.writeText(output.value); note.textContent = t('copied'); } catch { note.textContent = t('copyFail'); output.select(); } }));
  view.dialog.addEventListener('close', () => { output.value = ''; });
}
function createApplication(): void {
  if (busyMutation) return; const view = modal(t('createApp')); const form = el('form'); const [nameWrap, name] = field(t('name')); name.maxLength = 128;
  const [maxWrap, max] = field(t('max'), 'number', '8'); max.min = '0'; max.max = '1024'; max.step = '1';
  const approval = el('label', 'checkbox'); const checked = el('input'); checked.type = 'checkbox'; checked.checked = true; approval.append(checked, document.createTextNode(t('approve')));
  const submit = el('button', 'button primary', t('save')); submit.type = 'submit'; form.append(nameWrap, maxWrap, approval, submit); view.content.append(form);
  form.addEventListener('submit', event => { event.preventDefault(); if (!form.reportValidity() || busyMutation) return; const data = { name: name.value.trim(), max_connections: Number(max.value), require_target_approval: checked.checked }; view.dismiss(); mutate(t('createApp'), 'POST', '/v1/applications', data); });
}
function editRelay(row?: Row): void {
  if (busyMutation) return; const view=modal(row?t('edit'):t('createRelay')); const form=el('form'); view.content.append(el('p','muted',t('relayNote')));
  const fields: Array<[string,Word,number]>=[['name','name',128],['region','region',64],['endpoint','endpoint',512],['secret_ref','secretRef',64]];
  const inputs:Record<string,HTMLInputElement>={}; for(const [key,label,max] of fields){const [wrap,input]=field(t(label),'text',row?text(row[key]):''); input.maxLength=max; if(key==='region')input.required=false; inputs[key]=input;form.append(wrap);}
  const submit=el('button','button primary',t('save'));submit.type='submit';form.append(submit);view.content.append(form);
  form.addEventListener('submit',event=>{event.preventDefault();if(busyMutation || !form.reportValidity())return;const input:Row={};for(const [key,value] of Object.entries(inputs))input[key]=value.value.trim();view.dismiss();mutate(t('confirm'),row?'PATCH':'POST',row?`/v1/relay-nodes/${text(row['id'])}`:'/v1/relay-nodes',input);});
}
function editApplication(row: Row): void {
  if (busyMutation) return; const view = modal(t('edit')); const form = el('form');
  const [nameWrap, name] = field(t('name'), 'text', text(row['name'])); name.maxLength = 128;
  const [maxWrap, max] = field(t('max'), 'number', text(row['max_connections'])); max.min='0'; max.max='1024'; max.step='1';
  const approval = el('label','checkbox'); const checked = el('input'); checked.type='checkbox'; checked.checked=row['require_target_approval']===true; approval.append(checked,document.createTextNode(t('approve')));
  const submit=el('button','button primary',t('save')); submit.type='submit'; form.append(nameWrap,maxWrap,approval,submit); view.content.append(form);
  form.addEventListener('submit',event=>{event.preventDefault(); if(busyMutation || !form.reportValidity()) return; const input={name:name.value.trim(),max_connections:Number(max.value),require_target_approval:checked.checked}; view.dismiss(); mutate(t('confirm'),'PATCH',`/v1/applications/${text(row['id'])}`,input);});
}
function editDevice(row: Row): void {
  if (busyMutation) return; const view=modal(t('edit')); const form=el('form');
  const [nameWrap,name]=field(t('name'),'text',text(row['display_name'])); name.maxLength=128;
  const [maxWrap,max]=field(t('max'),'number',row['max_connections']==null?'':text(row['max_connections'])); max.required=false; max.min='0'; max.max='1024'; max.step='1';
  const connection=el('label','checkbox'); const enabled=el('input'); enabled.type='checkbox'; enabled.checked=row['connectable']===true; connection.append(enabled,document.createTextNode(t('connectable')));
  const objectField=(label:Word,value:unknown):[HTMLLabelElement,HTMLTextAreaElement]=>{const wrap=el('label','field'); const input=el('textarea'); input.value=JSON.stringify(value??{},null,2); input.maxLength=16384; input.rows=4; wrap.append(el('span','',t(label)),input); return[wrap,input];};
  const [tagsWrap,tags]=objectField('tags',row['tags']); const [metadataWrap,metadata]=objectField('metadata',row['metadata']); const error=el('div');
  const submit=el('button','button primary',t('save')); submit.type='submit'; form.append(nameWrap,maxWrap,connection,tagsWrap,metadataWrap,error,submit); view.content.append(form);
  form.addEventListener('submit',event=>{event.preventDefault(); if(busyMutation || !form.reportValidity()) return;
    try { const objects=[JSON.parse(tags.value) as unknown,JSON.parse(metadata.value) as unknown]; if(objects.some(value=>value===null || typeof value!=='object' || Array.isArray(value))) throw new Error();
      const input={display_name:name.value.trim(),max_connections:max.value===''?null:Number(max.value),connectable:enabled.checked,tags:objects[0],metadata:objects[1]}; view.dismiss(); mutate(t('confirm'),'PATCH',`/v1/devices/${text(row['id'])}`,input);
    } catch { error.replaceChildren(el('p','notice error',t('invalidJSON'))); }
  });
}
function createGrant(): void {
  if (busyMutation) return; const view = modal(t('grant')); const form = el('form'); const [sourceWrap, source] = field(t('source')); const [targetWrap, target] = field(t('target'));
  const [expiryWrap, expiry] = field(t('expiry'), 'datetime-local'); const later = new Date(Date.now() + 30 * 60_000); expiry.value = new Date(later.getTime() - later.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  const submit = el('button', 'button primary', t('save')); submit.type = 'submit'; form.append(sourceWrap, targetWrap, expiryWrap, submit); view.content.append(form);
  form.addEventListener('submit', event => { event.preventDefault(); if (!form.reportValidity() || busyMutation) return; const expires = new Date(expiry.value); if (Number.isNaN(expires.getTime())) return; const data = { source_device_id: source.value.trim(), target_device_id: target.value.trim(), expires_at: expires.toISOString(), expiry_action: 'terminate', max_sessions: 1 }; view.dismiss(); mutate(t('grant'), 'POST', '/v1/connection-grants', data); });
}
(async () => { root.append(el('p', 'empty', t('loading'))); try { session = await api('/auth/session') as Session; renderShell(); } catch { renderLogin(); } })();
