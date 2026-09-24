/*
 * VDI Hardening Scanner - giao dien web (khong phu thuoc thu vien ngoai)
 * Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
 * Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>
 */

'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = {
  checklist: null,
  checkById: {},
  remediable: new Set(),
  targets: [],
  credentials: [],
  scans: [],
  currentScan: null,
  settings: null,
  sse: null,
  activeJob: null,
};

const STATUS_LABEL = {
  PASS: 'Đã đạt', FAIL: 'Chưa đạt', WARN: 'Cần review',
  MANUAL: 'Thủ công', NA: 'Không áp dụng', ERROR: 'Lỗi',
};

// ------------------------------------------------------------------ tien ich

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Man hinh cho co logo VDI. An di khi ca hai deu ve 0:
 *    busyCount - so request dang chay
 *    busyHold  - so lan dang giu man hinh theo thoi gian (khoi dong, doi tab)
 *  Request thi hien tre 220ms cho khoi nhay; giu theo thoi gian thi hien ngay. */
const BOOT_SPIN_MS = 2200;   // lan dau mo trang - de kip nhin thay logo
const TAB_SPIN_MS = 420;     // moi lan doi tab - xoay mot ti cho muot

let busyCount = 0;
let busyHold = 0;
let busyTimer = null;

function loaderShow(label) {
  if (label) $('#loaderText').textContent = label;
  $('#loader').classList.add('on');
}

function loaderHideIfIdle() {
  if (busyCount > 0 || busyHold > 0) return;
  if (busyTimer !== null) { clearTimeout(busyTimer); busyTimer = null; }
  $('#loader').classList.remove('on');
  $('#loaderText').textContent = 'Đang xử lý…';
}

function busy(start, label) {
  if (!$('#loader')) return;
  if (start) {
    busyCount += 1;
    if (label) $('#loaderText').textContent = label;
    if (busyTimer === null && !$('#loader').classList.contains('on')) {
      busyTimer = setTimeout(() => { busyTimer = null; loaderShow(); }, 220);
    }
    return;
  }
  busyCount = Math.max(0, busyCount - 1);
  loaderHideIfIdle();
}

/** Giu man hinh cho it nhat `ms` mili giay, ke ca khi khong co request nao. */
async function holdLoader(ms, label) {
  if (!$('#loader')) return;
  busyHold += 1;
  loaderShow(label);
  try {
    await sleep(ms);
  } finally {
    busyHold = Math.max(0, busyHold - 1);
    loaderHideIfIdle();
  }
}

async function api(path, options = {}) {
  const opts = Object.assign({ headers: {} }, options);
  if (opts.body && typeof opts.body !== 'string') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  busy(true, options.label);
  let res, text;
  try {
    res = await fetch(path, opts);
    text = await res.text();
  } finally {
    busy(false);
  }
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const detail = data && data.detail;
    if (res.status === 423) {
      const err = new Error('Cần nhập lại mật khẩu');
      err.locked = JSON.parse(detail);
      throw err;
    }
    throw new Error(typeof detail === 'string' ? detail : (detail ? JSON.stringify(detail) : res.statusText));
  }
  return data;
}

/** Mật khẩu chỉ nằm trong RAM của tiến trình, nên sau khi khởi động lại tool
 *  phải nhập lại. Hàm này hỏi rồi nạp mật khẩu cho từng credential còn khoá. */
async function unlockCredentials(locked) {
  for (const c of locked.credentials) {
    const pw = prompt(`Nhập mật khẩu SSH cho "${c.name}" (user ${c.username}):`);
    if (!pw) return false;
    await api(`/api/credentials/${c.id}/unlock`, { method: 'POST', body: { password: pw } });
  }
  await loadCredentials();
  return true;
}

/** Gọi một hành động, nếu bị khoá thì hỏi mật khẩu rồi thử lại đúng 1 lần. */
async function withUnlock(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!e.locked) throw e;
    if (!(await unlockCredentials(e.locked))) { toast('Đã huỷ.', true); return null; }
    return await fn();
  }
}

let toastTimer = null;
function toast(msg, isErr = false) {
  let el = $('.toast');
  if (!el) {
    el = document.createElement('div');
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.className = 'toast' + (isErr ? ' err' : '');
  el.textContent = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.remove(), isErr ? 8000 : 4000);
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const linesToList = (text) => (text || '').split('\n').map((s) => s.trim()).filter(Boolean);

// ------------------------------------------------------------------ tabs

$$('nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    $$('nav button').forEach((b) => b.classList.remove('active'));
    $$('.tab').forEach((t) => t.classList.remove('active'));
    btn.classList.add('active');
    $('#tab-' + btn.dataset.tab).classList.add('active');
    holdLoader(TAB_SPIN_MS, 'Đang mở ' + btn.textContent.trim() + '…');
    if (btn.dataset.tab === 'deploy') renderDeploy();
    if (btn.dataset.tab === 'history') loadScans();
  });
});

function gotoTab(name) {
  const btn = $$('nav button').find((b) => b.dataset.tab === name);
  if (btn) btn.click();
}

// ------------------------------------------------------------------ nhat ky realtime

function openLog(scanId, title) {
  state.activeJob = scanId;
  $('#logTitle').textContent = title + ' — #' + scanId;
  $('#logBody').textContent = '';
  $('#logStatus').textContent = 'Đang chạy…';
  $('#logCancel').disabled = false;
  $('#logModal').classList.add('open');

  if (state.sse) state.sse.close();
  const src = new EventSource(`/api/scans/${scanId}/stream`);
  state.sse = src;

  src.onmessage = (ev) => {
    let line = '';
    try { line = JSON.parse(ev.data).line; } catch { return; }
    const body = $('#logBody');
    const atBottom = body.scrollTop + body.clientHeight >= body.scrollHeight - 40;
    if (line.startsWith('__JOB_END__')) {
      const ok = line.includes('status=done');
      $('#logStatus').textContent = ok ? '✅ Hoàn tất.' : '⚠️ Kết thúc: ' + line.replace('__JOB_END__ ', '');
      $('#logCancel').disabled = true;
      src.close();
      onJobFinished(scanId);
      return;
    }
    body.textContent += line + '\n';
    if (atBottom) body.scrollTop = body.scrollHeight;
  };
  src.onerror = () => {
    $('#logStatus').textContent = 'Mất kết nối luồng log. Bấm Đóng rồi mở lại từ tab Lịch sử.';
    src.close();
  };
}

async function onJobFinished(scanId) {
  await Promise.all([loadTargets(), loadScans()]);
  const scan = state.scans.find((s) => s.id === scanId);
  if (scan && scan.kind !== 'discovery') {
    $('#scanSelect').value = String(scanId);
    await renderScan(scanId);
    toast('Đã có report cho lần quét #' + scanId);
  } else {
    toast('Dò tìm xong. Danh sách máy chủ đã được cập nhật.');
  }
}

$('#logClose').addEventListener('click', () => {
  $('#logModal').classList.remove('open');
  if (state.sse) { state.sse.close(); state.sse = null; }
});

$('#logCancel').addEventListener('click', async () => {
  if (!state.activeJob) return;
  try {
    await api(`/api/scans/${state.activeJob}/cancel`, { method: 'POST' });
    toast('Đã gửi tín hiệu dừng.');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ health

async function loadHealth() {
  try {
    const h = await api('/api/health');
    const bits = [`${h.checks} tiêu chí`];
    bits.push(h.ansible ? 'ansible ✓' : '<span class="bad">thiếu ansible</span>');
    bits.push(h.sshpass ? 'sshpass ✓' : '<span class="bad">thiếu sshpass</span>');
    $('#health').innerHTML = bits.join(' · ');
  } catch {
    $('#health').innerHTML = '<span class="bad">không kết nối được backend</span>';
  }
}

// ------------------------------------------------------------------ checklist

async function loadChecklist() {
  state.checklist = await api('/api/checklist');
  state.checkById = {};
  state.checklist.checks.forEach((c) => { state.checkById[c.id] = c; });
  state.remediable = new Set(state.checklist.remediable);
}

// ------------------------------------------------------------------ credentials

async function loadCredentials() {
  state.credentials = await api('/api/credentials');
  const tbody = $('#credTable tbody');
  tbody.innerHTML = state.credentials.map((c) => `
    <tr>
      <td><strong>${esc(c.name)}</strong></td>
      <td class="mono">${esc(c.username)}</td>
      <td>${c.auth_type === 'key' ? 'SSH key' : 'Mật khẩu'}</td>
      <td>${c.port}</td>
      <td>${esc(c.become_method)}</td>
      <td>${c.auth_type === 'key'
            ? `<span class="pill PASS">key</span> <code class="mono">${esc(c.key_path || '')}</code>`
            : (c.unlocked ? '<span class="pill PASS">đã nhập mật khẩu</span>'
                          : '<span class="pill WARN">cần nhập mật khẩu</span>')}</td>
      <td>
        ${c.auth_type === 'password' ? `<button class="btn" data-unlock-cred="${c.id}" data-cred-name="${esc(c.name)}">Nhập mật khẩu</button> ` : ''}
        <button class="btn danger" data-del-cred="${c.id}">Xoá</button>
      </td>
    </tr>`).join('');
  $('#credEmpty').style.display = state.credentials.length ? 'none' : 'block';

  const opts = ['<option value="">— chọn credential —</option>']
    .concat(state.credentials.map((c) => `<option value="${c.id}">${esc(c.name)} (${esc(c.username)})</option>`));
  $('#assignCred').innerHTML = opts.join('');

  tbody.querySelectorAll('[data-del-cred]').forEach((b) => {
    b.addEventListener('click', async () => {
      if (!confirm('Xoá credential này?')) return;
      try {
        await api('/api/credentials/' + b.dataset.delCred, { method: 'DELETE' });
        await Promise.all([loadCredentials(), loadTargets()]);
        toast('Đã xoá credential.');
      } catch (e) { toast(e.message, true); }
    });
  });

  tbody.querySelectorAll('[data-unlock-cred]').forEach((b) => {
    b.addEventListener('click', async () => {
      const pw = prompt(`Nhập mật khẩu SSH cho "${b.dataset.credName}":`);
      if (!pw) return;
      try {
        await api(`/api/credentials/${b.dataset.unlockCred}/unlock`, { method: 'POST', body: { password: pw } });
        await loadCredentials();
        toast('Đã nạp mật khẩu vào bộ nhớ phiên này.');
      } catch (e) { toast(e.message, true); }
    });
  });
}

$('#crType').addEventListener('change', () => {
  const isKey = $('#crType').value === 'key';
  $('#crKeyWrap').style.display = isKey ? '' : 'none';
  $('#crPassWrap').style.display = isKey ? 'none' : '';
});

$('#btnAddCred').addEventListener('click', async () => {
  const payload = {
    name: $('#crName').value.trim(),
    username: $('#crUser').value.trim(),
    auth_type: $('#crType').value,
    port: parseInt($('#crPort').value, 10) || 22,
    become_method: $('#crBecome').value,
    become_password: $('#crSudo').value || null,
    key_path: $('#crKey').value.trim() || null,
    password: $('#crPass').value || null,
  };
  if (!payload.name || !payload.username) { toast('Cần nhập tên và username.', true); return; }
  try {
    await api('/api/credentials', { method: 'POST', body: payload });
    ['#crName', '#crUser', '#crKey', '#crPass', '#crSudo'].forEach((s) => { $(s).value = ''; });
    await loadCredentials();
    toast('Đã lưu credential.');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ targets

async function loadTargets() {
  state.targets = await api('/api/targets');
  const tbody = $('#hostTable tbody');
  tbody.innerHTML = state.targets.map((t) => `
    <tr>
      <td><input type="checkbox" class="host-cb" value="${t.id}"></td>
      <td class="mono"><strong>${esc(t.ip)}</strong></td>
      <td>${esc(t.hostname || '—')}</td>
      <td>${t.port}</td>
      <td>${t.credential_name ? esc(t.credential_name) : '<span class="pill FAIL">chưa gán</span>'}</td>
      <td>${esc(t.os_name || '—')}</td>
      <td class="mono">${esc((t.last_seen || '—').replace('T', ' ').slice(0, 19))}</td>
      <td><button class="btn danger" data-del-host="${t.id}">Xoá</button></td>
    </tr>`).join('');
  $('#hostEmpty').style.display = state.targets.length ? 'none' : 'block';

  tbody.querySelectorAll('[data-del-host]').forEach((b) => {
    b.addEventListener('click', async () => {
      if (!confirm('Xoá host này khỏi danh sách?')) return;
      await api('/api/targets/' + b.dataset.delHost, { method: 'DELETE' });
      await loadTargets();
    });
  });
}

const selectedHostIds = () => $$('.host-cb:checked').map((c) => parseInt(c.value, 10));

$('#hostAll').addEventListener('change', (e) => {
  $$('.host-cb').forEach((c) => { c.checked = e.target.checked; });
});
$('#btnSelectAll').addEventListener('click', () => {
  $$('.host-cb').forEach((c) => { c.checked = true; });
  $('#hostAll').checked = true;
});
$('#btnSelectNone').addEventListener('click', () => {
  $$('.host-cb').forEach((c) => { c.checked = false; });
  $('#hostAll').checked = false;
});

$('#btnAssign').addEventListener('click', async () => {
  const ids = selectedHostIds();
  const credId = $('#assignCred').value;
  if (!ids.length) { toast('Chưa chọn host nào.', true); return; }
  if (!credId) { toast('Chưa chọn credential.', true); return; }
  try {
    await api('/api/targets/assign-credential', {
      method: 'POST',
      body: { target_ids: ids, credential_id: parseInt(credId, 10) },
    });
    await loadTargets();
    toast(`Đã gán credential cho ${ids.length} host.`);
  } catch (e) { toast(e.message, true); }
});

$('#btnAddHost').addEventListener('click', async () => {
  const ip = prompt('Nhập IP hoặc hostname của máy chủ:');
  if (!ip) return;
  try {
    await api('/api/targets', { method: 'POST', body: { ip: ip.trim(), port: 22 } });
    await loadTargets();
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ discovery

$('#btnPreview').addEventListener('click', async () => {
  try {
    const r = await api('/api/discovery/preview', {
      method: 'POST',
      body: { spec: $('#specInput').value, port: 22 },
    });
    $('#previewOut').textContent =
      `Sẽ quét ${r.count} địa chỉ. Ví dụ: ${r.sample.join(', ')}${r.count > r.sample.length ? ' …' : ''}`;
  } catch (e) { $('#previewOut').textContent = '⚠️ ' + e.message; }
});

$('#btnDiscover').addEventListener('click', async () => {
  const spec = $('#specInput').value.trim();
  if (!spec) { toast('Chưa nhập dải IP.', true); return; }
  try {
    const r = await api('/api/discovery', {
      method: 'POST',
      label: 'Đang khởi tạo phiên dò tìm…',
      body: { spec, port: parseInt($('#specPort').value, 10) || 22, resolve_names: true },
    });
    openLog(r.scan_id, 'Dò tìm host');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ audit

$('#btnAudit').addEventListener('click', async () => {
  const ids = selectedHostIds();
  if (!ids.length) { toast('Chưa chọn host nào để quét.', true); return; }
  const noCred = state.targets.filter((t) => ids.includes(t.id) && !t.credential_id);
  if (noCred.length) {
    toast(`${noCred.length} host chưa gán credential: ${noCred.map((t) => t.ip).join(', ')}`, true);
    return;
  }
  try {
    const r = await withUnlock(() =>
      api('/api/scans', {
        method: 'POST',
        label: 'Đang khởi tạo phiên quét…',
        body: { kind: 'audit', target_ids: ids },
      }));
    if (r) openLog(r.scan_id, 'Quét đánh giá');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ ket qua

async function loadScans() {
  state.scans = await api('/api/scans');
  const scannable = state.scans.filter((s) => s.kind !== 'discovery');

  const cur = $('#scanSelect').value;
  $('#scanSelect').innerHTML = scannable.map((s) =>
    `<option value="${s.id}">#${s.id} · ${s.kind === 'audit' ? 'Quét đánh giá' : 'Triển khai'} · ${esc((s.created_at || '').replace('T', ' ').slice(0, 19))} · ${esc(s.status)}</option>`
  ).join('');
  if (cur && scannable.some((s) => String(s.id) === cur)) $('#scanSelect').value = cur;

  ['#cmpBefore', '#cmpAfter'].forEach((sel) => {
    $(sel).innerHTML = scannable.map((s) => `<option value="${s.id}">#${s.id} · ${esc(s.kind)} · ${esc((s.created_at || '').slice(0, 19).replace('T', ' '))}</option>`).join('');
  });

  $('#scanTable tbody').innerHTML = state.scans.map((s) => `
    <tr>
      <td>#${s.id}</td>
      <td>${s.kind === 'discovery' ? 'Dò tìm' : s.kind === 'audit' ? 'Quét đánh giá' : 'Triển khai'}</td>
      <td><span class="pill ${s.status === 'done' ? 'PASS' : s.status === 'running' ? 'WARN' : s.status === 'failed' ? 'FAIL' : 'MANUAL'}">${esc(s.status)}</span></td>
      <td class="mono">${esc((s.started_at || '—').replace('T', ' ').slice(0, 19))}</td>
      <td class="mono">${esc((s.finished_at || '—').replace('T', ' ').slice(0, 19))}</td>
      <td>${esc(s.message || '')}</td>
      <td><button class="btn" data-log="${s.id}">Xem log</button></td>
    </tr>`).join('');

  $('#scanTable tbody').querySelectorAll('[data-log]').forEach((b) => {
    b.addEventListener('click', async () => {
      const id = parseInt(b.dataset.log, 10);
      const data = await api(`/api/scans/${id}/log`);
      $('#logTitle').textContent = 'Nhật ký — #' + id;
      $('#logBody').textContent = data.lines.join('\n');
      $('#logStatus').textContent = data.finished ? 'Đã kết thúc.' : 'Đang chạy…';
      $('#logCancel').disabled = data.finished;
      state.activeJob = id;
      $('#logModal').classList.add('open');
      $('#logBody').scrollTop = $('#logBody').scrollHeight;
    });
  });
}

$('#scanSelect').addEventListener('change', () => renderScan(parseInt($('#scanSelect').value, 10)));
$('#btnReloadScan').addEventListener('click', () => renderScan(parseInt($('#scanSelect').value, 10)));
$('#filterStatus').addEventListener('change', () => renderScanBody());

async function renderScan(scanId) {
  if (!scanId) return;
  state.currentScan = await api('/api/scans/' + scanId);
  $('#btnCsv').href = `/api/scans/${scanId}/report.csv`;
  $('#btnHtml').href = `/api/scans/${scanId}/report.html`;

  const totals = state.currentScan.totals;
  const order = ['PASS', 'FAIL', 'WARN', 'MANUAL', 'NA', 'ERROR'];
  $('#scanStats').innerHTML = order
    .filter((k) => totals[k])
    .map((k) => `<div class="stat"><div class="n" style="color:var(--${k === 'PASS' ? 'pass' : k === 'FAIL' ? 'fail' : k === 'WARN' ? 'warn' : 'muted'})">${totals[k]}</div><div class="k">${STATUS_LABEL[k]}</div></div>`)
    .join('') || '<div class="empty">Chưa có dữ liệu.</div>';

  renderScanBody();
}

function renderScanBody() {
  if (!state.currentScan) return;
  const filter = $('#filterStatus').value;
  const out = state.currentScan.hosts.map((host) => {
    if (!host.ok) {
      return `<div class="panel"><h2>${esc(host.ip)}</h2>
        <div class="warnbox">Không lấy được kết quả: ${esc(host.error || 'lỗi không xác định')}</div></div>`;
    }
    const rows = host.results.filter((r) => !filter || r.effective_status === filter);
    const f = host.facts;
    return `<div class="panel">
      <h2>${esc(host.ip)} — ${esc(f.os_name || 'không rõ')}</h2>
      <p class="hint">Hostname: ${esc(f.hostname || '—')} · RAM ${esc(f.ram_gb)} GB · ${esc(f.cpu_count)} vCPU ·
        Ảo hoá: ${esc(f.virtualization || '—')} · Kernel ${esc(f.kernel || '—')}</p>
      <div class="scroll-x"><table>
        <thead><tr>
          <th style="width:76px">Mã</th><th style="width:22%">Tiêu chí</th>
          <th style="width:24%">Yêu cầu mức đạt</th><th style="width:96px">Kết quả</th>
          <th>Thực tế ghi nhận</th><th style="width:120px">Đánh giá tay</th>
        </tr></thead>
        <tbody>${rows.map((r) => resultRow(host, r)).join('')}</tbody>
      </table></div>
      ${rows.length ? '' : '<div class="empty">Không có mục nào khớp bộ lọc.</div>'}
    </div>`;
  }).join('');
  $('#scanHosts').innerHTML = out || '<div class="empty">Lần quét này chưa có host nào.</div>';
  bindManualMarks();
}

function resultRow(host, r) {
  const evidence = r.evidence
    ? `<details class="evidence"><summary>Bằng chứng</summary><pre>${esc(r.evidence)}</pre></details>` : '';
  const manualCell = (r.mode === 'manual' || r.status === 'MANUAL' || r.status === 'WARN')
    ? `<select class="mark" data-ip="${esc(host.ip)}" data-check="${r.check_id}">
         <option value="">—</option>
         <option value="PASS"${r.manual_status === 'PASS' ? ' selected' : ''}>Đạt</option>
         <option value="FAIL"${r.manual_status === 'FAIL' ? ' selected' : ''}>Chưa đạt</option>
         <option value="NA"${r.manual_status === 'NA' ? ' selected' : ''}>Không áp dụng</option>
       </select>` : '';
  const note = r.note ? `<div class="sev" style="margin-top:4px">ℹ️ ${esc(r.note)}</div>` : '';
  return `<tr>
    <td class="mono">${esc(r.check_id)}<div class="sev ${esc(r.severity)}">${esc(r.severity)}</div></td>
    <td>${esc(r.title)}${r.remediable ? '<div class="sev">🔧 tự động khắc phục được</div>' : ''}</td>
    <td class="sev">${esc(r.expected || '')}</td>
    <td><span class="pill ${esc(r.effective_status)}">${esc(r.effective_status)}</span>
        ${r.manual_status ? '<div class="sev">(đánh giá tay)</div>' : ''}</td>
    <td>${esc(r.actual || '')}${note}${evidence}</td>
    <td>${manualCell}</td>
  </tr>`;
}

function bindManualMarks() {
  $$('.mark').forEach((sel) => {
    sel.addEventListener('change', async () => {
      try {
        await api('/api/manual-marks', {
          method: 'POST',
          body: { ip: sel.dataset.ip, check_id: sel.dataset.check, status: sel.value },
        });
        toast(sel.value
          ? 'Đã lưu đánh giá thủ công cho ' + sel.dataset.check
          : 'Đã bỏ đánh giá thủ công cho ' + sel.dataset.check);
        await renderScan(state.currentScan.scan.id);
      } catch (e) { toast(e.message, true); }
    });
  });
}

$('#btnToDeploy').addEventListener('click', () => {
  if (!state.currentScan) { toast('Chưa chọn lần quét nào.', true); return; }
  const failed = new Set();
  const hostIds = new Set();
  const idByIp = Object.fromEntries(state.targets.map((t) => [t.ip, t.id]));
  state.currentScan.hosts.forEach((h) => {
    if (idByIp[h.ip] !== undefined) hostIds.add(idByIp[h.ip]);
    h.results.forEach((r) => {
      if (['FAIL', 'ERROR'].includes(r.effective_status) && state.remediable.has(r.check_id)) {
        failed.add(r.check_id);
      }
    });
  });
  if (!failed.size) { toast('Không có mục chưa đạt nào có thể tự động khắc phục.'); return; }
  gotoTab('deploy');
  renderDeploy(Array.from(failed), Array.from(hostIds));
  toast(`Đã chọn sẵn ${failed.size} mục cần khắc phục.`);
});

// ------------------------------------------------------------------ trien khai

const SAFE_CHECKS = new Set([
  'OS-02', 'OS-03', 'OS-11', 'OS-15', 'OS-16', 'OS-20', 'OS-21', 'OS-22',
  'OS-23', 'OS-24', 'OS-25', 'OS-26', 'OS-28', 'OS-29', 'OS-31', 'OS-34',
  'OS-35', 'OS-38', 'OS-42', 'OS-45',
]);

const RISKY_NOTE = {
  'OS-05': 'Bật SSH AllowGroups — cần khai báo user quản trị, sai là mất quyền truy cập.',
  'OS-09': 'Tắt đăng nhập root qua SSH — cần chắc chắn có user quản trị khác.',
  'OS-10': 'Bật firewall — cần khai báo dải IP quản trị.',
  'OS-14': 'Sửa GRUB, cần REBOOT mới có hiệu lực.',
  'OS-18': 'Gỡ card mạng ảo virbr0 — không chạy trên host ảo hoá KVM.',
  'OS-27': 'Bật pam_wheel cho lệnh su — cần user quản trị trong group wheel.',
  'OS-30': 'Siết cấu hình SSH — kiểm tra client cũ có hỗ trợ MAC mạnh không.',
  'OS-36': 'Bật firewall khi khởi động.',
};

function renderDeploy(preselect = null, preselectHosts = null) {
  if (!state.checklist) return;

  const s = state.settings || {};
  const warns = [];
  if (!(s.admin_users || []).length) warns.push('Chưa khai báo <strong>User quản trị</strong> → các mục OS-05, OS-27 sẽ bị bỏ qua.');
  if (!(s.admin_networks || []).length) warns.push('Chưa khai báo <strong>Dải IP quản trị</strong> → mục OS-10 (firewall) sẽ bị bỏ qua.');
  if (!(s.ntp_servers || []).length) warns.push('Chưa khai báo <strong>NTP server nội bộ</strong> → mục OS-03 sẽ bị bỏ qua.');
  if (!(s.log_servers || []).length) warns.push('Chưa khai báo <strong>Log server</strong> → OS-35 chỉ bật rsyslog, không cấu hình forward.');
  $('#deployWarn').innerHTML = warns.length
    ? '⚠️ ' + warns.join('<br>⚠️ ') + '<br>Vào tab <strong>Cấu hình</strong> để bổ sung.'
    : '✅ Cấu hình đầy đủ, mọi mục đều có thể triển khai.';
  $('#deployWarn').style.display = 'block';

  const preHosts = preselectHosts ? new Set(preselectHosts) : null;
  $('#deployHosts').innerHTML = state.targets.map((t) => `
    <label><input type="checkbox" class="dep-host" value="${t.id}"${preHosts && preHosts.has(t.id) ? ' checked' : ''}>
      <span class="t">${esc(t.ip)} <code>${esc(t.hostname || '')}</code>
      ${t.credential_id ? '' : '<span class="pill FAIL">chưa gán credential</span>'}</span></label>`).join('')
    || '<div class="empty">Chưa có host nào.</div>';

  const pre = preselect ? new Set(preselect) : null;
  const items = state.checklist.checks.filter((c) => c.remediable);
  $('#deployChecks').innerHTML = items.map((c) => `
    <label>
      <input type="checkbox" class="dep-check" value="${c.id}"${pre && pre.has(c.id) ? ' checked' : ''}>
      <span class="t"><code>${esc(c.id)}</code> ${esc(c.title)}
        ${RISKY_NOTE[c.id] ? `<div class="sev" style="color:var(--warn)">⚠ ${esc(RISKY_NOTE[c.id])}</div>` : ''}
      </span>
    </label>`).join('');
}

$('#btnCheckAll').addEventListener('click', () => $$('.dep-check').forEach((c) => { c.checked = true; }));
$('#btnCheckNone').addEventListener('click', () => $$('.dep-check').forEach((c) => { c.checked = false; }));
$('#btnCheckSafe').addEventListener('click', () =>
  $$('.dep-check').forEach((c) => { c.checked = SAFE_CHECKS.has(c.value); }));

$('#btnDeploy').addEventListener('click', async () => {
  const hosts = $$('.dep-host:checked').map((c) => parseInt(c.value, 10));
  const checks = $$('.dep-check:checked').map((c) => c.value);
  if (!hosts.length) { toast('Chưa chọn máy chủ nào.', true); return; }
  if (!checks.length) { toast('Chưa chọn mục hardening nào.', true); return; }

  const risky = checks.filter((c) => RISKY_NOTE[c]);
  const msg = `Triển khai ${checks.length} mục trên ${hosts.length} máy chủ?` +
    (risky.length ? `\n\nCác mục có rủi ro cần xác nhận:\n- ${risky.map((c) => c + ': ' + RISKY_NOTE[c]).join('\n- ')}` : '');
  if (!confirm(msg)) return;

  try {
    const r = await withUnlock(() => api('/api/scans', {
      method: 'POST',
      label: 'Đang khởi tạo phiên triển khai…',
      body: { kind: 'remediate', target_ids: hosts, check_ids: checks },
    }));
    if (r) openLog(r.scan_id, 'Triển khai hardening');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ settings

async function loadSettings() {
  const s = await api('/api/settings');
  state.settings = s;
  $('#stTimezone').value = s.timezone;
  $('#stNofile').value = s.nofile_min;
  $('#stNproc').value = s.nproc_min;
  $('#stConntrack').value = s.conntrack_max_min;
  $('#stHashsize').value = s.conntrack_hashsize;
  $('#stTmout').value = s.tmout;
  $('#stOpenssl').value = s.openssl_min_version;
  $('#stNtp').value = (s.ntp_servers || []).join('\n');
  $('#stLog').value = (s.log_servers || []).join('\n');
  $('#stRepo').value = (s.internal_repo_hosts || []).join('\n');
  $('#stAdminNet').value = (s.admin_networks || []).join('\n');
  $('#stAdminUser').value = (s.admin_users || []).join('\n');
  $('#stBizUser').value = (s.business_users || []).join('\n');
  $('#stUnowned').checked = !!s.unowned_scan;
  $('#stReboot').checked = !!s.allow_reboot_changes;
  $('#stVirbr').checked = !!s.remove_virtual_nic;
}

$('#btnSaveSettings').addEventListener('click', async () => {
  const body = {
    timezone: $('#stTimezone').value.trim(),
    nofile_min: parseInt($('#stNofile').value, 10),
    nproc_min: parseInt($('#stNproc').value, 10),
    conntrack_max_min: parseInt($('#stConntrack').value, 10),
    conntrack_hashsize: parseInt($('#stHashsize').value, 10),
    tmout: parseInt($('#stTmout').value, 10),
    openssl_min_version: $('#stOpenssl').value.trim(),
    ntp_servers: linesToList($('#stNtp').value),
    log_servers: linesToList($('#stLog').value),
    internal_repo_hosts: linesToList($('#stRepo').value),
    admin_networks: linesToList($('#stAdminNet').value),
    admin_users: linesToList($('#stAdminUser').value),
    business_users: linesToList($('#stBizUser').value),
    unowned_scan: $('#stUnowned').checked,
    allow_reboot_changes: $('#stReboot').checked,
    remove_virtual_nic: $('#stVirbr').checked,
  };
  try {
    state.settings = await api('/api/settings', { method: 'PUT', body });
    toast('Đã lưu cấu hình.');
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ so sanh

$('#btnCompare').addEventListener('click', async () => {
  const before = $('#cmpBefore').value;
  const after = $('#cmpAfter').value;
  if (!before || !after || before === after) { toast('Chọn 2 lần quét khác nhau.', true); return; }
  try {
    const r = await api(`/api/compare?before=${before}&after=${after}`);
    $('#compareOut').innerHTML = `
      <div class="stats">
        <div class="stat"><div class="n" style="color:var(--pass)">${r.fixed}</div><div class="k">Đã khắc phục</div></div>
        <div class="stat"><div class="n" style="color:var(--fail)">${r.regressed}</div><div class="k">Xấu đi</div></div>
        <div class="stat"><div class="n">${r.changes.length}</div><div class="k">Tổng thay đổi</div></div>
      </div>
      <div class="scroll-x"><table>
        <thead><tr><th>Host</th><th>Mã</th><th>Tiêu chí</th><th>Trước</th><th>Sau</th></tr></thead>
        <tbody>${r.changes.map((c) => `<tr>
          <td class="mono">${esc(c.host)}</td><td class="mono">${esc(c.check_id)}</td><td>${esc(c.title)}</td>
          <td><span class="pill ${esc(c.before || 'NA')}">${esc(c.before || '—')}</span></td>
          <td><span class="pill ${esc(c.after || 'NA')}">${esc(c.after || '—')}</span></td>
        </tr>`).join('')}</tbody>
      </table></div>`;
  } catch (e) { toast(e.message, true); }
});

// ------------------------------------------------------------------ khoi dong

(async function init() {
  // Chay song song voi phan nap du lieu: du nap xong som van giu logo du lau.
  const boot = holdLoader(BOOT_SPIN_MS, 'Đang khởi động…');
  try {
    await loadChecklist();
    await Promise.all([loadHealth(), loadCredentials(), loadTargets(), loadSettings(), loadScans()]);
    const first = $('#scanSelect').value;
    if (first) await renderScan(parseInt(first, 10));
  } catch (e) {
    toast('Không khởi tạo được giao diện: ' + e.message, true);
  } finally {
    // Overlay bat dau o trang thai hien (xem index.html) de che luc trang con trong.
    await boot;
    busyCount = 0;
    loaderHideIfIdle();
  }
})();
