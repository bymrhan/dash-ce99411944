import { decrypt, deriveKeyBytes, importKey, parseHeader } from './vault.js';

const DATA_URL = 'private-data.enc';
const REFRESH_MS = 5 * 60 * 1000;
const PAGE_ROWS = 200;
const SESSION_ITEM = 'streamops-session';
// BLOCKED: our route is refused (Cloudflare/WAF/country), not the account. IN_USE: fine, every connection slot taken.
const SEVERITY = { UNREACHABLE: 0, BLOCKED: 1, DISABLED: 2, EXPIRED: 3, WARNING: 4, PENDING: 5, IN_USE: 6, HEALTHY: 7 };
const STATUS_LABELS = { HEALTHY: 'HEALTHY', WARNING: 'WARNING', EXPIRED: 'EXPIRED', DISABLED: 'DISABLED', UNREACHABLE: 'UNREACHABLE', PENDING: 'BEKLİYOR', IN_USE: 'KULLANIMDA', BLOCKED: 'ENGELLİ' };
const ROUTE_NAMES = { direct: 'Doğrudan', mirror: 'Ayna', proxy: 'Proxy' };
const TYPE_NAMES = { xtream: 'XTREAM', stalker: 'STALKER', m3u: 'M3U', custom: 'ÖZEL API' };
const unknownExpiry = (a) => a.expDate == null && a.type && a.type !== 'xtream';

// The password is dropped as soon as the key is derived; the key itself is a non-exportable
// CryptoKey. How long it outlives a page load is decided below ("remembered key").
const state = { key: null, data: null, search: '', group: '', status: '', sortKey: 'severity', sortDir: 1, limit: PAGE_ROWS };
state.view = 'accounts';
state.forumSearch = '';
state.forumLimit = 100;

const $ = (id) => document.getElementById(id);

// All exported text goes through textContent; nothing is ever injected as HTML.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return el;
}

const nowS = () => Math.floor(Date.now() / 1000);
const statusOf = (a) => a.status || 'PENDING';
const fmtDate = (s) => (s ? new Date(s * 1000).toLocaleDateString('tr-TR') : '—');
const fmtDateTime = (s) => (s ? new Date(s * 1000).toLocaleString('tr-TR') : '—');
const dash = (v) => (v === null || v === undefined || v === '' ? '—' : v);
const daysLeft = (a) => (a.expDate == null ? null : Math.ceil((a.expDate - nowS()) / 86400));
const servingMirror = (a) => Boolean(a.activeBaseUrl) && a.activeBaseUrl !== a.baseUrl;
const base64 = (bytes) => btoa(String.fromCharCode(...bytes));

function ago(s) {
  if (!s) return '—';
  const d = Math.max(0, nowS() - s);
  if (d < 60) return 'az önce';
  if (d < 3600) return `${Math.floor(d / 60)} dk önce`;
  if (d < 86400) return `${Math.floor(d / 3600)} sa önce`;
  return `${Math.floor(d / 86400)} gün önce`;
}

function toast(message, isError = false) {
  const el = h('div', { class: `toast${isError ? ' error' : ''}` }, message);
  $('toasts').append(el);
  setTimeout(() => el.remove(), isError ? 7000 : 3000);
}

// ---- remembered key ---------------------------------------------------------
// Default (session): the key bytes are encrypted with a random, non-exportable wrapping key. The
// wrapped bytes go to sessionStorage, the wrapping key to IndexedDB; neither is of any use alone,
// and sessionStorage is emptied by the browser when the tab's session ends. So a reload does not
// ask again, a new session does, and nothing that could open the data stays behind.
// "Bu cihazda hatırla" (opt-in): the data key itself is kept in IndexedDB until "Kilitle".

const session = {
  get() { try { return sessionStorage.getItem(SESSION_ITEM); } catch { return null; } },
  set(value) { try { sessionStorage.setItem(SESSION_ITEM, value); } catch { /* asks again on reload */ } },
  clear() { try { sessionStorage.removeItem(SESSION_ITEM); } catch { /* nothing stored */ } },
};

function keyStore(mode, action) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('streamops-dashboard', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('keys', mode);
      const request = action(tx.objectStore('keys'));
      tx.oncomplete = () => { open.result.close(); resolve(request.result); };
      tx.onerror = () => { open.result.close(); reject(tx.error); };
    };
  });
}

// Storage can be unavailable (private windows); the page then simply asks on every load.
const quiet = (promise) => promise.catch(() => null);

function forgetKey() {
  session.clear();
  return quiet(keyStore('readwrite', (store) => store.delete('key')));
}

// `bytes` are the raw key bytes; the caller wipes them afterwards.
async function saveKey(key, bytes, header, remember) {
  const record = { salt: base64(header.salt), iterations: header.iterations, remember };
  session.clear();
  if (remember) record.key = key;
  else {
    record.key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, record.key, bytes));
    session.set(`${base64(iv)}.${base64(wrapped)}`);
  }
  if (await quiet(keyStore('readwrite', (store) => store.put(record, 'key'))) === null) session.clear();
}

async function savedKey(header) {
  const record = await quiet(keyStore('readonly', (store) => store.get('key')));
  if (!record) return null;
  try {
    if (record.salt !== base64(header.salt) || record.iterations !== header.iterations) throw new Error('other password');
    if (record.remember) return record.key;
    const [iv, wrapped] = session.get().split('.').map((part) => Uint8Array.from(atob(part), (ch) => ch.charCodeAt(0)));
    const bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, record.key, wrapped));
    try {
      return await importKey(bytes);
    } finally {
      bytes.fill(0);
    }
  } catch {
    // A new browser session, another master password or a leftover from an old one: start over.
    await forgetKey();
    return null;
  }
}
// ---- loading ----------------------------------------------------------------

async function fetchFile() {
  const response = await fetch(DATA_URL, { cache: 'no-store' });
  if (!response.ok) throw new Error(`${DATA_URL} alınamadı (HTTP ${response.status})`);
  return parseHeader(await response.arrayBuffer());
}

function showLock(message = '') {
  state.key = null;
  state.data = null;
  $('rows').replaceChildren();
  if ($('detail').open) $('detail').close();
  $('detail-body').replaceChildren();
  $('app').hidden = true;
  $('lock').hidden = false;
  $('lock-error').hidden = !message;
  $('lock-error').textContent = message;
  $('password').value = '';
  $('password').focus();
}

function showData(data) {
  state.data = data;
  $('lock').hidden = true;
  $('app').hidden = false;
  render();
}

async function boot() {
  let file;
  try {
    file = await fetchFile();
  } catch (err) {
    return showLock(err.message);
  }
  const key = await savedKey(file);
  if (!key) return showLock();
  try {
    state.key = key;
    return showData(await decrypt(key, file));
  } catch {
    await forgetKey();
    return showLock();
  }
}

async function unlock(event) {
  event.preventDefault();
  const button = $('unlock-btn');
  button.disabled = true;
  button.textContent = 'Çözülüyor…';
  try {
    const file = await fetchFile();
    const bytes = await deriveKeyBytes($('password').value, file);
    $('password').value = '';
    let data;
    try {
      const key = await importKey(bytes);
      try {
        data = await decrypt(key, file);
      } catch {
        throw new Error('Parola hatalı.');
      }
      state.key = key;
      await saveKey(key, bytes, file, $('remember').checked);
    } finally {
      bytes.fill(0);
    }
    showData(data);
  } catch (err) {
    showLock(err.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Kilidi aç';
  }
}

async function refresh({ silent = false } = {}) {
  if (!state.key) return;
  try {
    const file = await fetchFile();
    showData(await decrypt(state.key, file));
    if (!silent) toast('Güncellendi');
  } catch (err) {
    // A changed master password makes the old key useless: ask again.
    if (err.name === 'OperationError') {
      await forgetKey();
      showLock('Ana parola değişmiş; yeniden girin.');
    } else if (!silent) toast(err.message, true);
  }
}

async function lock() {
  await forgetKey();
  showLock();
}

// ---- table ------------------------------------------------------------------

const COLUMNS = [
  ['severity', 'Durum', (a) => SEVERITY[statusOf(a)]],
  ['name', 'Hesap', (a) => a.name.toLocaleLowerCase('tr')],
  ['host', 'Panel', (a) => a.host],
  ['exp', 'Bitiş', (a) => a.expDate ?? Infinity],
  ['cons', 'Bağlantı', (a) => a.activeCons ?? -1],
  ['streams', 'Kategori / Kanal', (a) => a.liveStreams ?? -1],
  ['route', 'Rota', (a) => a.lastGoodRoute || ''],
  ['check', 'Son kontrol', (a) => a.lastCheckAt ?? 0],
  ['reason', 'Açıklama', null],
];

function filtered() {
  const needle = state.search.trim().toLocaleLowerCase('tr');
  const sorter = COLUMNS.find(([key]) => key === state.sortKey)[2];
  return state.data.accounts
    .filter((a) => {
      if (state.status && statusOf(a) !== state.status) return false;
      if (state.group && a.group !== state.group) return false;
      if (!needle) return true;
      return [a.name, a.group, a.host, a.username, a.notes, a.xtStatus, a.status, a.reasons.join(' ')].join(' ').toLocaleLowerCase('tr').includes(needle);
    })
    .sort((x, y) => {
      const a = sorter(x);
      const b = sorter(y);
      if (a !== b) return (a < b ? -1 : 1) * state.sortDir;
      return x.name.localeCompare(y.name, 'tr');
    });
}

const badge = (status) => h('span', { class: `badge s-${status}` }, h('i', { class: 'dot' }), STATUS_LABELS[status]);

function expiryCell(a) {
  if (unknownExpiry(a)) return h('td', {}, 'Bildirilmedi');
  if (a.expDate === null) return h('td', {}, a.lastSuccessAt ? 'Süresiz' : '—');
  const days = daysLeft(a);
  const cls = days <= 0 ? 'bad' : days <= state.data.settings.expiryWarningDays ? 'warn' : 'muted';
  return h('td', {}, fmtDate(a.expDate), h('div', { class: cls }, days <= 0 ? 'süresi doldu' : `${days} gün kaldı`));
}

function connCell(a) {
  if (a.activeCons === null && a.maxConnections === null) return h('td', {}, '—');
  const full = a.maxConnections > 0 && a.activeCons >= a.maxConnections;
  return h('td', { class: `num${full ? ' bad' : ''}` }, `${dash(a.activeCons)} / ${a.maxConnections > 0 ? a.maxConnections : '∞'}`);
}

function routeText(a) {
  const route = a.lastGoodRoute ? ROUTE_NAMES[a.lastGoodRoute] || a.lastGoodRoute : '—';
  return a.routeMode && a.routeMode !== 'auto' ? `${route} (sabit: ${ROUTE_NAMES[a.routeMode] || a.routeMode})` : route;
}

function row(a) {
  const status = statusOf(a);
  const failing = a.consecutiveFailures > 0 && !['UNREACHABLE', 'DISABLED', 'BLOCKED'].includes(status);
  return h('tr', { onclick: () => openDetail(a) },
    h('td', {}, badge(status), failing && h('span', { class: 'tag alert' }, `${a.consecutiveFailures}/${state.data.settings.failThreshold} hata`)),
    h('td', {},
      h('div', { class: 'name' }, a.name, a.type && a.type !== 'xtream' && h('span', { class: 'tag' }, TYPE_NAMES[a.type] || a.type.toUpperCase()), a.isTrial && h('span', { class: 'tag' }, 'TRIAL'), !a.enabled && h('span', { class: 'tag' }, 'DURAKLATILDI')),
      h('div', { class: 'muted' }, [a.group, a.username].filter(Boolean).join(' · ')),
    ),
    h('td', { class: 'mono' }, a.host,
      servingMirror(a) && h('span', { class: 'tag alert' }, 'AYNA'),
      a.mirrors.length > 0 && !servingMirror(a) && h('span', { class: 'tag' }, `+${a.mirrors.length}`),
      a.xtStatus && h('div', { class: 'muted' }, a.xtStatus)),
    expiryCell(a),
    connCell(a),
    h('td', { class: 'num' }, `${dash(a.liveCategories)} / ${dash(a.liveStreams)}`),
    h('td', {}, routeText(a), a.lastGoodProxy && h('div', { class: 'muted mono' }, a.lastGoodProxy)),
    h('td', { title: fmtDateTime(a.lastCheckAt) }, ago(a.lastCheckAt), a.latencyMs !== null && h('div', { class: 'muted' }, `${a.latencyMs} ms`)),
    h('td', { class: 'wrap muted' }, failing ? a.lastError : a.reasons.join('; ')),
  );
}

function render() {
  renderSections();
  const { accounts, exportedAt, settings } = state.data;
  $('meta').textContent = `${accounts.length} hesap · dışa aktarım ${fmtDateTime(exportedAt)} (${ago(exportedAt)})`;
  // Exports stopped arriving: say so instead of showing old statuses as current.
  const staleAfterS = Math.max(3 * 3600, settings.checkIntervalMinutes * 60 * 6);
  $('stale').hidden = nowS() - exportedAt < staleAfterS;
  $('stale').textContent = `Bu veri ${ago(exportedAt)} alındı; dışa aktarım durmuş olabilir.`;

  const counts = {};
  for (const a of accounts) counts[statusOf(a)] = (counts[statusOf(a)] || 0) + 1;
  const cards = [['', 'TOPLAM', accounts.length], ...Object.keys(SEVERITY).reverse().map((s) => [s, STATUS_LABELS[s], counts[s] || 0])]
    .filter(([key, , count]) => key !== 'PENDING' || count > 0);
  $('cards').replaceChildren(...cards.map(([key, label, count]) =>
    h('button', {
      class: `card${key ? ` s-${key}` : ''}`, type: 'button', 'aria-pressed': String(state.status === key),
      onclick: () => { state.status = key; state.limit = PAGE_ROWS; render(); },
    }, h('span', {}, key && h('i', { class: 'dot' }), label), h('b', {}, count)),
  ));

  const groups = [...new Set(accounts.map((a) => a.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'tr'));
  if (state.group && !groups.includes(state.group)) state.group = '';
  $('group').replaceChildren(...[['', 'Tüm gruplar'], ...groups.map((g) => [g, g])].map(([value, label]) => h('option', { value, selected: value === state.group }, label)));
  $('group').hidden = groups.length === 0;

  $('head').replaceChildren(...COLUMNS.map(([key, label, sorter]) =>
    h('th', {
      class: sorter ? 'sortable' : null,
      'aria-sort': state.sortKey === key ? (state.sortDir === 1 ? 'ascending' : 'descending') : null,
      onclick: sorter && (() => {
        state.sortDir = state.sortKey === key ? -state.sortDir : 1;
        state.sortKey = key;
        render();
      }),
    }, label),
  ));

  const list = filtered();
  $('rows').replaceChildren(...list.slice(0, state.limit).map(row));
  $('empty').hidden = list.length > 0;
  $('more').hidden = list.length <= state.limit;
  $('more-btn').textContent = `${list.length - state.limit} hesap daha göster`;
}

// ---- detail -----------------------------------------------------------------

function snapshotTable(headers, rows) {
  return h('div', { class: 'panel table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, headers.map(label => h('th', {}, label)))),
    h('tbody', {}, rows.map(row => h('tr', {}, row.map(value => h('td', { class: 'wrap' }, value ?? '—'))))),
  ), !rows.length && h('p', { class: 'empty' }, 'Henüz kayıt yok.'));
}

function renderSections() {
  const sections = [['accounts', 'Hesaplar'], ['content', 'İçerikler'], ['tasks', 'Görevler'], ['quality', 'Sunucu kalitesi'], ['proxies', 'Proxyler'], ['domains', 'Alan adları'], ['forum', 'Forum / adres değişiklikleri']];
  $('navigation').replaceChildren(...sections.map(([key, label]) => h('button', { class: `btn${state.view === key ? ' primary' : ''}`, type: 'button', 'aria-pressed': String(state.view === key), onclick: () => { state.view = key; renderSections(); } }, label)));
  $('account-section').hidden = state.view !== 'accounts';
  const body = $('dashboard-section'); body.hidden = state.view === 'accounts';
  const d = state.data.dashboard || {};
  const accountNames = new Map(state.data.accounts.map(a => [a.id, a.name]));
  const name = id => accountNames.get(id) || id || '—';
  const title = sections.find(([key]) => key === state.view)?.[1];
  const content = [];
  if (state.view === 'content') content.push(snapshotTable(['Hesap', 'Canlı kategori', 'Kanal', 'Film kategorisi / film', 'Dizi kategorisi / dizi', 'Ülkeler'], state.data.accounts.map(a => [name(a.id), a.liveCategories, a.liveStreams, `${dash(a.library?.vodCategories)} / ${dash(a.library?.vodStreams)}`, `${dash(a.library?.seriesCategories)} / ${dash(a.library?.series)}`, (a.countries || []).join(', ')])));
  if (state.view === 'tasks') {
    content.push(snapshotTable(['Görev', 'Hesap', 'Tür', 'Durum', 'Deneme', 'Zaman', 'Sonuç'], (d.tasks || []).map(t => [t.id, name(t.account_id), t.type, t.status, t.attempt, fmtDateTime(t.finished_at || t.created_at), t.summary || t.error])));
    content.push(h('h2', {}, 'Son durum değişiklikleri'), snapshotTable(['Hesap', 'Zaman', 'Önce', 'Sonra', 'Açıklama'], (d.events || []).map(e => [name(e.account_id), fmtDateTime(e.ts), e.from_status, e.to_status, e.reason])));
  }
  if (state.view === 'quality') content.push(snapshotTable(['Sunucu', 'Durum', 'Toplam', 'Hız', 'Kararlılık', 'Yayın', 'API (ms)', 'Güncelleme'], (d.quality || []).map(q => [q.host, q.state, q.score, q.speed_score, q.stability_score, q.stream_score, q.last_api_ms, fmtDateTime(q.updated_at)])));
  if (state.view === 'proxies') content.push(snapshotTable(['Proxy', 'Durum', 'Gecikme (ms)', 'Çıkış IP', 'Son kontrol', 'Hata'], (d.proxies || []).map(p => [p.label, p.ok == null ? 'Bekliyor' : p.ok ? 'Çalışıyor' : 'Başarısız', p.latency_ms, p.exit_ip, fmtDateTime(p.checked_at), p.error])));
  if (state.view === 'domains') content.push(snapshotTable(['Alan adı', 'Not'], (d.domains || []).map(x => [x.domain, x.notes])));
  if (state.view === 'forum') {
    const f = d.forum || {}, archive = f.archive || {};
    const search = h('input', { type: 'search', value: state.forumSearch, placeholder: 'Forum arşivinde domain, yazar veya mesaj ara', oninput: event => { state.forumSearch = event.target.value; state.forumLimit = 100; renderForumRows(); } });
    const rows = h('div', {});
    const renderForumRows = () => {
      const list = (f.history || []).filter(r => [r.old_url, r.new_url, r.author, r.note].join(' ').toLocaleLowerCase('tr').includes(state.forumSearch.toLocaleLowerCase('tr')));
      rows.replaceChildren(snapshotTable(['Zaman', 'Hesap', 'Eski → yeni', 'Durum', 'Mesaj', 'Kaynak'], list.slice(0, state.forumLimit).map(r => [fmtDateTime(r.ts), name(r.account_id), [r.old_url, r.new_url].filter(Boolean).join(' → '), { review: 'İnceleme gerekli', updated: 'Güncellendi', announcement: 'Duyuru', error: 'Hata' }[r.status] || r.status, r.note, safeForumLink(r.source, r.author)])),
        list.length > state.forumLimit && h('button', { class: 'btn', type: 'button', onclick: () => { state.forumLimit += 200; renderForumRows(); } }, `${list.length - state.forumLimit} kayıt daha göster`));
    };
    renderForumRows();
    content.push(h('p', { class: 'sub' }, `Arşiv: ${Math.min((archive.next_page || 1) - 1, archive.last_page || 0)} / ${archive.last_page || 0} sayfa · ${archive.posts || 0} mesaj · Son kontrol: ${fmtDateTime(f.state?.checked_at)}`),
      f.state?.error && h('p', { class: 'bad' }, f.state.error), search, rows);
  }
  body.replaceChildren(h('h2', {}, title), h('p', { class: 'sub' }, `Yerel StreamOps sonuçları · ${fmtDateTime(state.data.exportedAt)} tarihli veri. İşlemler yerel panelde başlatılır.`), ...content);
}

function safeForumLink(source, author) {
  try {
    const url = new URL(source);
    if (url.protocol === 'https:' && url.hostname === 'forumsitesi.com.tr') return h('a', { href: url.href, target: '_blank', rel: 'noopener noreferrer' }, author || 'Duyuru');
  } catch { /* invalid imported source */ }
  return '—';
}

async function copy(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} kopyalandı`);
  } catch {
    toast('Panoya kopyalanamadı', true);
  }
}

function field(label, value, { mono = false, copyable = false } = {}) {
  if (value === null || value === undefined || value === '') return null;
  return h('div', { class: 'field' },
    h('span', {}, label),
    h('b', { class: mono ? 'mono' : null }, value),
    copyable && h('button', { class: 'btn small ghost', type: 'button', onclick: () => copy(String(value), label) }, 'Kopyala'),
  );
}

function secretField(label, value) {
  if (!value) return null;
  const shown = h('b', { class: 'mono' }, '••••••••');
  const toggle = h('button', { class: 'btn small ghost', type: 'button', onclick: () => {
    const reveal = toggle.textContent === 'Göster';
    shown.textContent = reveal ? value : '••••••••';
    toggle.textContent = reveal ? 'Gizle' : 'Göster';
  } }, 'Göster');
  return h('div', { class: 'field' }, h('span', {}, label), shown, toggle,
    h('button', { class: 'btn small ghost', type: 'button', onclick: () => copy(value, label) }, 'Kopyala'));
}

function m3uLink(a) {
  if (a.type === 'm3u') {
    if (!a.playlistUrl) return null;
    try {
      const url = new URL(a.playlistUrl);
      if (!['http:', 'https:'].includes(url.protocol)) return null;
      if (a.authMode === 'query' && a.token && a.tokenName) url.searchParams.set(a.tokenName, a.token);
      return url.toString();
    } catch { return null; }
  }
  if ((a.type && a.type !== 'xtream') || !a.username || !a.password) return null;
  return `${a.activeBaseUrl || a.baseUrl}/get.php?username=${encodeURIComponent(a.username)}&password=${encodeURIComponent(a.password)}&type=m3u_plus&output=ts`;
}

function openDetail(a) {
  const link = m3uLink(a);
  const days = daysLeft(a);
  $('detail-body').replaceChildren(
    h('div', { class: 'modal-head' },
      h('div', {}, h('h2', {}, a.name), h('p', { class: 'sub' }, [a.group, a.host].filter(Boolean).join(' · '))),
      h('button', { class: 'btn small ghost', type: 'button', onclick: () => $('detail').close() }, 'Kapat'),
    ),
    h('div', { class: 'fields' },
      h('div', { class: 'field' }, h('span', {}, 'Durum'), badge(statusOf(a)), a.xtStatus && h('span', { class: 'muted' }, a.xtStatus)),
      field('Panel URL', a.baseUrl, { mono: true, copyable: true }),
      field('Protokol', TYPE_NAMES[a.type || 'xtream'] || a.type),
      servingMirror(a) && field('Etkin ayna', a.activeBaseUrl, { mono: true, copyable: true }),
      field(a.type === 'stalker' ? 'MAC' : 'Kullanıcı adı', a.username, { mono: true, copyable: true }),
      secretField('Parola', a.password),
      a.type === 'm3u' && secretField('Playlist URL', a.playlistUrl),
      a.type === 'custom' && secretField('API URL', a.customApiUrl),
      a.type === 'custom' && secretField('Yayın URL şablonu', a.streamTemplate),
      (a.type === 'm3u' || a.type === 'custom') && field('Kimlik doğrulama', { none: 'Yok', bearer: 'Authorization: Bearer', header: `HTTP başlığı: ${a.tokenName || ''}`, query: `URL parametresi: ${a.tokenName || ''}` }[a.authMode || 'none']),
      secretField('Token', a.token),
      a.credError && h('div', { class: 'field bad' }, 'Giriş bilgileri dışa aktarılırken çözülemedi.'),
      link && h('div', { class: 'field' }, h('span', {}, 'M3U'), h('button', { class: 'btn small', type: 'button', onclick: () => copy(link, 'M3U bağlantısı') }, 'Bağlantıyı kopyala')),
      a.type === 'm3u' && ['bearer', 'header'].includes(a.authMode) && h('div', { class: 'field muted' }, 'Oynatıcıda URL ile birlikte yukarıdaki HTTP kimlik doğrulama başlığını ayarlayın.'),
      a.type === 'custom' && h('div', { class: 'field muted' }, 'Bu hizmet Xtream uyumlu JSON sözleşmesi kullanır; standart get.php bağlantısı üretilmez.'),
      field('Bitiş', a.expDate ? `${fmtDateTime(a.expDate)} (${days <= 0 ? 'süresi doldu' : `${days} gün kaldı`})` : unknownExpiry(a) ? 'Sağlayıcı bildirmedi' : a.lastSuccessAt ? 'Süresiz' : null),
      (a.type === 'm3u' || a.type === 'stalker') && a.maxConnections == null && field('Bağlantı limiti', 'Sağlayıcı bildirmedi'),
      field('Bağlantı', a.maxConnections === null ? null : `${dash(a.activeCons)} / ${a.maxConnections > 0 ? a.maxConnections : '∞'}`),
      field('Kategori / kanal', a.liveStreams === null ? null : `${dash(a.liveCategories)} / ${a.liveStreams}`),
      a.library && field('Film kategorisi / film', `${dash(a.library.vodCategories)} / ${dash(a.library.vodStreams)}`),
      a.library && field('Dizi kategorisi / dizi', `${dash(a.library.seriesCategories)} / ${dash(a.library.series)}`),
      field('Rota', a.lastGoodRoute ? `${routeText(a)}${a.lastGoodProxy ? ` · ${a.lastGoodProxy}` : ''} (${fmtDateTime(a.lastGoodRouteAt)})` : null),
      field('Doğrudan rota', a.directState),
      field('M3U doğrulama', a.m3uOk === null ? null : a.m3uOk ? 'Geçerli' : 'Hatalı'),
      field('Son kontrol', fmtDateTime(a.lastCheckAt)),
      field('Son başarılı kontrol', fmtDateTime(a.lastSuccessAt)),
      field('Durum değişimi', fmtDateTime(a.statusChangedAt)),
      field('Hesap oluşturulma', a.createdAtRemote ? fmtDateTime(a.createdAtRemote) : null),
      field('Açıklama', a.reasons.join('; ')),
      field('Son hata', a.lastError ? `${a.lastError} (${fmtDateTime(a.lastErrorAt)})` : null),
      field('İçerik ülkeleri', a.countries.join(', ')),
      a.mirrors.length > 0 && h('div', { class: 'field' }, h('span', {}, 'Yan paneller'), h('div', { class: 'mono' }, a.mirrors.map((m) => h('div', {}, m)))),
      field('Not', a.notes),
    ),
  );
  $('detail').showModal();
}

// ---- wiring -----------------------------------------------------------------

$('unlock').addEventListener('submit', unlock);
$('lock-btn').addEventListener('click', lock);
$('refresh').addEventListener('click', () => refresh());
$('search').addEventListener('input', (event) => { state.search = event.target.value; state.limit = PAGE_ROWS; render(); });
$('group').addEventListener('change', (event) => { state.group = event.target.value; state.limit = PAGE_ROWS; render(); });
$('more-btn').addEventListener('click', () => { state.limit += PAGE_ROWS * 5; render(); });
$('detail').addEventListener('click', (event) => { if (event.target === $('detail')) $('detail').close(); });
$('detail').addEventListener('close', () => $('detail-body').replaceChildren());
setInterval(() => refresh({ silent: true }), REFRESH_MS);

// Never render inside someone else's frame (a <meta> CSP cannot say frame-ancestors).
if (window.top === window.self) boot();
