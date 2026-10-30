// FireX administration console. Brand strings come from /api/system,
// never from this file -- see include/brand.h.

const ZONE_COLORS = {
    WAN:'#FF3B5C', LAN:'#00E58B', DMZ:'#FFC247', GUEST:'#4FC3F7',
    IOT:'#B07CFF', VOIP:'#00D4D4', MGMT:'#FF4B2B', QUARANTINE:'#7A879B',
    VPN:'#7C9CFF'
};

const fmt = n => (n || 0).toLocaleString();
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const state = { user: null, role: null, csrf: null };
const isAdmin = () => state.role === 'admin';

class AuthError extends Error {}

async function api(path, opts) {
    const o = Object.assign({ cache: 'no-store', headers: {} }, opts || {});
    if (o.body !== undefined && typeof o.body !== 'string') {
        o.body = JSON.stringify(o.body);
        o.headers['Content-Type'] = 'application/json';
    }
    // Every state-changing call carries the session's CSRF token: the cookie
    // on its own is deliberately not enough to act.
    if (state.csrf && o.method && o.method !== 'GET')
        o.headers['X-FireX-CSRF'] = state.csrf;

    const r = await fetch(path, o);
    if (r.status === 401) { state.csrf = null; throw new AuthError('signed out'); }

    const text = await r.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { raw: text }; }
    if (!r.ok) throw new Error(data.error || (path + ' -> ' + r.status));
    return data;
}

function toast(msg, bad) {
    let el = document.getElementById('toast');
    if (!el) {
        el = document.createElement('div');
        el.id = 'toast';
        document.body.appendChild(el);
    }
    el.className = bad ? 'toast bad show' : 'toast show';
    el.textContent = msg;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove('show'), 4000);
}

function zoneChip(z) {
    return `<span class="zone-chip" style="--zc:${ZONE_COLORS[z] || '#888'}">${esc(z)}</span>`;
}

/* ── accounts ──────────────────────────────────────────────── */

/*
 * Two databases, one page. The FireX user file gates this console and the
 * serial menu; the Linux account gates SSH and the shell. They ship with
 * root/root and admin/admin, which is why the banner is loud.
 */

const SYS_LABEL = {
    set:      ['ok',   'Changed'],
    default:  ['bad',  'Still default'],
    locked:   ['warn', 'No password'],
    absent:   ['mut',  'No Linux account'],
    unknown:  ['warn', 'Unreadable'],
    /* Which accounts are still on a shipped password is withheld from a
     * read-only session. Rendered as its own state rather than falling
     * through to "Changed", which would be a lie told by a default. */
    redacted: ['mut',  'Not shown']
};

async function renderAccounts() {
    const d = await api('/api/accounts');
    state.minPassword = d.min_password;

    const rows = d.accounts.map(a => {
        const [cls, label] = SYS_LABEL[a.system] || SYS_LABEL.absent;
        const con = a.role === '-'
            ? '<span class="muted">&mdash;</span>'
            : (a.console_default === null || a.console_default === undefined
                ? '<span class="pill mut">Not shown</span>'
                : (a.console_default
                    ? '<span class="pill bad">Still default</span>'
                    : '<span class="pill ok">Changed</span>'));
        return `
      <tr>
        <td class="mono"><b>${esc(a.user)}</b>${a.user === d.self
              ? ' <span class="muted small">(you)</span>' : ''}</td>
        <td>${a.role === '-' ? '<span class="muted">&mdash;</span>'
                             : esc(a.role)}</td>
        <td>${con}</td>
        <td><span class="pill ${cls}">${label}</span></td>
      </tr>`;
    }).join('');

    const redacted = d.redacted ? `
      <div class="note">Password state is not shown to a read-only session.
      Sign in as an administrator to see which accounts are still on the
      password they shipped with.</div>` : '';

    const warn = (d.defaults || 0) > 0 ? `
    <div class="panel danger-panel">
      <h3>${d.defaults} account${d.defaults === 1 ? ' is' : 's are'} still on the shipped password</h3>
      <p class="small">FireX ships <b class="mono">root</b>/<b class="mono">root</b>
         and <b class="mono">admin</b>/<b class="mono">admin</b> so a new appliance is
         always reachable. Anyone who can see port 22 or 8080 knows them too.
         Change both before this box faces anything you do not control.</p>
    </div>` : '';

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>System &amp; Accounts</h1>${roleBadge()}</div>
    ${warn}${redacted}
    <div class="panel">
      <h3>Accounts</h3>
      <p class="muted small">
        <b>Console</b> is the FireX user file &mdash; this web console and the serial menu.
        <b>Linux</b> is the system account &mdash; SSH and the shell behind the menu.</p>
      <table class="dt">
        <thead><tr><th>User</th><th>Role</th><th>Console password</th><th>Linux password</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="muted">No accounts.</td></tr>'}</tbody>
      </table>
    </div>
    ${isAdmin() ? `
    <div class="panel">
      <h3>Change a password</h3>
      <form id="pw-form" class="capform pwform" autocomplete="off">
        <label>Account
          <select name="user">
            ${d.accounts.map(a => `<option value="${esc(a.user)}">${esc(a.user)}</option>`).join('')}
          </select></label>
        <label>Applies to
          <select name="scope">
            <option value="console">Console (web UI + serial menu)</option>
            <option value="system">Linux (SSH + shell)</option>
          </select></label>
        <label>New password
          <input name="password" type="password" minlength="${d.min_password}"
                 autocomplete="new-password" required></label>
        <label>Repeat
          <input name="confirm" type="password" minlength="${d.min_password}"
                 autocomplete="new-password" required></label>
        <button class="mini primary" type="submit">Set password</button>
      </form>
      <p class="muted small">At least ${d.min_password} characters, and never the
         account name &mdash; that is what shipped.</p>
    </div>` : `
    <div class="panel">
      <p class="muted">This account is read-only. An administrator changes passwords.</p>
    </div>`}`;

    const form = document.getElementById('pw-form');
    if (form) form.addEventListener('submit', async ev => {
        ev.preventDefault();
        const f = new FormData(form);
        const pass = f.get('password');
        if (pass !== f.get('confirm')) { toast('The passwords do not match', true); return; }

        const btn = form.querySelector('button');
        btn.disabled = true;
        try {
            const r = await api('/api/accounts/password', {
                method: 'POST',
                body: { user: f.get('user'), scope: f.get('scope'), password: pass }
            });
            form.reset();
            if (r.reauth) {
                // That was this session's own console password; the cookie is gone.
                state.user = state.role = state.csrf = null;
                chrome(false);
                renderLogin('Password changed. Sign in again.');
                return;
            }
            toast(r.status || 'Password changed');
            show('accounts');
        } catch (e) { toast(e.message, true); btn.disabled = false; }
    });
}

async function renderVLANs() {
    const d = await api('/api/vlans');

    const rows = d.vlans.map(v => `
      <tr>
        <td><b>${v.vlan_id}</b></td>
        <td>${esc(v.name)}</td>
        <td>${zoneChip(v.zone)}</td>
        <td class="mono">${esc(v.subnet)}/${v.cidr}</td>
        <td class="mono">${esc(v.gateway)}</td>
        <td>${v.dhcp ? `<span class="ok">&#10003;</span> ${esc(v.dhcp_start)}&ndash;${esc(v.dhcp_end)}`
                     : '<span class="muted">&mdash;</span>'}</td>
        <td>${v.internet ? '<span class="ok">&#10003;</span>' : '<span class="no">&#10007;</span>'}</td>
        <td>${v.inter_vlan ? '<span class="ok">&#10003;</span>' : '<span class="no">&#10007;</span>'}</td>
        <td>${v.isolation ? '<span class="warn">&#128274;</span>' : '<span class="muted">&mdash;</span>'}</td>
        <td>${v.clients}</td>
        <td class="mono">${fmt(v.rx_packets)}</td>
        <td class="mono danger">${fmt(v.blocked)}</td>
      </tr>`).join('');

    const ports = d.ports.map(p => `
      <tr>
        <td class="mono"><b>${esc(p.ifname)}</b></td>
        <td>${esc(p.label)}</td>
        <td><span class="mode-chip mode-${esc(p.mode.toLowerCase())}">${esc(p.mode)}</span></td>
        <td>${zoneChip(p.zone)}</td>
        <td class="mono">${p.pvid || '&mdash;'}</td>
        <td class="mono small">${p.allowed_vlans.length ? p.allowed_vlans.join(', ') : '&mdash;'}</td>
        <td>${p.link_up ? `<span class="ok">&#9679; ${p.speed}M</span>`
                        : '<span class="no">&#9679; down</span>'}</td>
        <td class="mono">${fmt(p.rx_packets)}</td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
    <div class="page-head">
      <h1>Network Segmentation</h1>
      ${roleBadge()}
    </div>

    <div class="kpi-row">
      <div class="kpi"><div class="kpi-n">${d.vlans.length}</div><div class="kpi-l">VLANs</div></div>
      <div class="kpi"><div class="kpi-n">${d.ports.length}</div><div class="kpi-l">Ports</div></div>
      <div class="kpi"><div class="kpi-n">${d.acl_count}</div><div class="kpi-l">ACL Rules</div></div>
      <div class="kpi ok"><div class="kpi-n">${fmt(d.stats.allowed)}</div><div class="kpi-l">Inter-VLAN Allowed</div></div>
      <div class="kpi danger"><div class="kpi-n">${fmt(d.stats.denied)}</div><div class="kpi-l">Inter-VLAN Denied</div></div>
      <div class="kpi warn"><div class="kpi-n">${fmt(d.stats.violations)}</div><div class="kpi-l">Tag Violations</div></div>
    </div>

    <div class="panel">
      <h3>VLAN Segments</h3>
      <table class="dt">
        <thead><tr>
          <th>VID</th><th>Name</th><th>Zone</th><th>Subnet</th><th>Gateway</th>
          <th>DHCP Scope</th><th>WAN</th><th>Route</th><th>Iso</th>
          <th>Clients</th><th>RX</th><th>Blocked</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Physical Ports (802.1Q)</h3>
      <table class="dt">
        <thead><tr>
          <th>Interface</th><th>Label</th><th>Mode</th><th>Zone</th>
          <th>PVID</th><th>Allowed VLANs</th><th>Link</th><th>RX</th>
        </tr></thead>
        <tbody>${ports}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Zone Forwarding Matrix</h3>
      <p class="muted small">Row = source zone &middot; Column = destination zone.</p>
      ${renderMatrix(d.zones, d.matrix)}
    </div>`;
}

function renderMatrix(zones, matrix) {
    let h = `<table class="matrix"><thead><tr><th class="corner">FROM \\ TO</th>`;
    zones.forEach(z => h += `<th style="--zc:${ZONE_COLORS[z] || '#888'}">${esc(z)}</th>`);
    h += `</tr></thead><tbody>`;

    zones.forEach((from, i) => {
        h += `<tr><th style="--zc:${ZONE_COLORS[from] || '#888'}">${esc(from)}</th>`;
        zones.forEach((to, j) => {
            if (i === j) { h += `<td class="m-self">&mdash;</td>`; return; }
            const a = matrix[i][j];
            const cls = (a === 'DENY' || a === 'LOG_DENY') ? 'm-deny'
                      : a === 'LOG_ALLOW' ? 'm-log' : 'm-allow';
            const sym = a === 'ALLOW' ? '&#10003;' : a === 'LOG_ALLOW' ? '&#9680;'
                      : a === 'LOG_DENY' ? '&#9673;' : '&#10007;';
            const act = isAdmin()
                ? ` data-from="${esc(from)}" data-to="${esc(to)}" data-act="${esc(a)}" class="${cls} editable"`
                : ` class="${cls}"`;
            h += `<td${act} title="${esc(from)} &rarr; ${esc(to)}: ${esc(a)}${
                isAdmin() ? ' (click to cycle)' : ''}">${sym}</td>`;
        });
        h += `</tr>`;
    });
    return h + `</tbody></table>
    <div class="legend">
      <span><i class="m-allow"></i> Allow</span>
      <span><i class="m-log"></i> Allow + Log</span>
      <span><i class="m-deny"></i> Deny</span>
    </div>`;
}

async function renderBlockEvents() {
    const d = await api('/api/blockpage/events');
    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Block Events</h1>${roleBadge()}</div>
    <div class="kpi-row">
      <div class="kpi"><div class="kpi-n">${fmt(d.pages_served)}</div><div class="kpi-l">Pages Served</div></div>
      <div class="kpi warn"><div class="kpi-n">${fmt(d.override_requests)}</div><div class="kpi-l">Access Requests</div></div>
      <div class="kpi"><div class="kpi-n">${d.events.length}</div><div class="kpi-l">Recent Events</div></div>
    </div>
    <div class="panel"><table class="dt">
      <thead><tr><th>Time</th><th>Request ID</th><th>Client</th><th>VLAN</th>
      <th>Zone</th><th>Destination</th><th>Reason</th><th>Policy</th><th>Sev</th></tr></thead>
      <tbody>${d.events.slice().reverse().map(e => `
        <tr>
          <td class="small">${new Date(e.time * 1000).toLocaleTimeString()}</td>
          <td class="mono small">${esc(e.request_id)}</td>
          <td class="mono">${esc(e.client_ip)}</td>
          <td>${esc(e.vlan_name)} <span class="muted">(${e.vlan_id})</span></td>
          <td>${zoneChip(e.zone)}</td>
          <td class="small">${esc(e.host) || '&mdash;'}</td>
          <td>${esc(e.reason)}</td>
          <td class="mono small">${esc(e.policy_id)}</td>
          <td><span class="sev s${e.severity}">${e.severity}</span></td>
        </tr>`).join('')}
      </tbody></table></div>`;
}

/* ── WAN links and failover ────────────────────────────────── */

const STATUS_CLS = {
    up: 'ok', down: 'no', unmonitored: 'muted', unknown: 'warn'
};

async function renderWAN() {
    const d = await api('/api/wan');

    const rows = d.links.map(w => `
      <tr>
        <td class="mono"><b>${esc(w.ifname)}</b>${w.active
            ? ' <span class="active-pill">ACTIVE</span>' : ''}</td>
        <td>${esc(w.mode)}</td>
        <td class="mono">${w.mode === 'static' ? esc(w.ip) : '<span class="muted">—</span>'}</td>
        <td class="mono">${esc(w.monitor_ip) || '<span class="muted">not monitored</span>'}</td>
        <td><span class="${STATUS_CLS[w.status] || 'muted'}">&#9679; ${esc(w.status)}</span></td>
        <td class="mono">${w.status === 'up' && w.rtt_ms > 0
            ? w.rtt_ms.toFixed(1) + ' ms' : '<span class="muted">—</span>'}</td>
        <td class="mono ${w.loss_pct > 0 ? 'warn' : ''}">${w.loss_pct}%</td>
        <td class="mono">${w.priority}${w.backup ? ' <span class="muted small">(backup)</span>' : ''}</td>
        <td class="mono small">${fmt(w.probes)} / <span class="${
            w.failures ? 'danger' : 'muted'}">${fmt(w.failures)}</span></td>
        <td class="small">${w.last_change
            ? new Date(w.last_change * 1000).toLocaleTimeString() : '<span class="muted">—</span>'}</td>
      </tr>`).join('');

    const active = d.active >= 0 ? d.links[d.active] : null;

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>WAN &amp; Failover</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi ${active ? 'ok' : 'danger'}">
        <div class="kpi-n">${active ? esc(active.ifname) : 'none'}</div>
        <div class="kpi-l">Carrying Default Route</div></div>
      <div class="kpi"><div class="kpi-n">${d.links.length}</div><div class="kpi-l">WAN Links</div></div>
      <div class="kpi"><div class="kpi-n">${d.interval}s</div><div class="kpi-l">Probe Interval</div></div>
      <div class="kpi"><div class="kpi-n">${d.fail_threshold}</div><div class="kpi-l">Misses To Fail Over</div></div>
      <div class="kpi"><div class="kpi-n">${d.ok_threshold}</div><div class="kpi-l">Replies To Recover</div></div>
    </div>

    ${active ? '' : `<div class="panel"><p class="no">
      No WAN link is currently usable. Either every monitored link is down, or
      none has been probed yet.</p></div>`}

    <div class="panel">
      <h3>Links</h3>
      <table class="dt">
        <thead><tr>
          <th>Interface</th><th>Mode</th><th>Address</th><th>Monitor</th>
          <th>Status</th><th>RTT</th><th>Loss</th><th>Priority</th>
          <th>Probes / Fails</th><th>Changed</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p class="muted small" style="margin-top:12px">
        The lowest priority among the links that are up carries the default
        route. A link must miss ${d.fail_threshold} probes in a row before it
        is declared down, and answer ${d.ok_threshold} in a row to come back.
      </p>
    </div>`;
}

/* ── aliases, schedules and routes ─────────────────────────── */

async function renderPolicy() {
    const d = await api('/api/policy');

    const aliases = d.aliases.map(a => `
      <tr>
        <td class="mono"><b>$${esc(a.name)}</b></td>
        <td><span class="mode-chip mode-${a.kind === 'port' ? 'trunk' : 'access'}">${esc(a.kind)}</span></td>
        <td class="mono small">${esc(a.entries)}</td>
        <td>${a.count}</td>
        <td class="mono">${fmt(a.hits)}</td>
        <td class="small">${esc(a.description)}</td>
        <td>${isAdmin()
            ? `<button class="mini" data-alias-edit="${esc(a.name)}"
                       data-entries="${esc(a.entries)}">Edit</button>
               <button class="mini" data-alias-del="${esc(a.name)}">Delete</button>`
            : '<span class="muted">—</span>'}</td>
      </tr>`).join('');

    const scheds = d.schedules.map(s => `
      <tr>
        <td><b>${esc(s.name)}</b></td>
        <td>${esc(s.days)}</td>
        <td class="mono">${esc(s.start)}–${esc(s.end)}</td>
        <td>${s.active ? '<span class="ok">&#9679; active now</span>'
                       : '<span class="muted">&#9679; outside window</span>'}</td>
        <td class="small">${esc(s.description)}</td>
      </tr>`).join('');

    const routes = d.routes.map(r => `
      <tr>
        <td class="mono"><b>${esc(r.dest)}/${r.cidr}</b></td>
        <td class="mono">${esc(r.gateway)}</td>
        <td class="mono">${esc(r.ifname) || '<span class="muted">—</span>'}</td>
        <td class="mono">${r.metric}</td>
        <td class="small">${esc(r.description)}</td>
      </tr>`).join('');

    const shaping = await shapingPanel();

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Policy Objects</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi"><div class="kpi-n">${d.aliases.length}</div><div class="kpi-l">Aliases</div></div>
      <div class="kpi"><div class="kpi-n">${d.schedules.length}</div><div class="kpi-l">Schedules</div></div>
      <div class="kpi"><div class="kpi-n">${d.routes.length}</div><div class="kpi-l">Static Routes</div></div>
      <div class="kpi warn"><div class="kpi-n">${fmt(d.schedule_skipped)}</div>
        <div class="kpi-l">Off-Hours Skips</div></div>
    </div>

    <div class="panel">
      <h3>Aliases ${isAdmin() ? '<button class="mini primary" id="alias-new">New alias</button>' : ''}</h3>
      <p class="muted small">Rules reference these as <span class="mono">$NAME</span>.
         Editing one changes every rule that uses it.</p>
      <table class="dt">
        <thead><tr><th>Name</th><th>Kind</th><th>Entries</th><th>#</th>
          <th>Hits</th><th>Description</th><th></th></tr></thead>
        <tbody>${aliases || '<tr><td colspan="7" class="muted">None defined.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Schedules</h3>
      <p class="muted small">A rule carrying a schedule is skipped outside its
         window; evaluation carries on to whatever follows it.</p>
      <table class="dt">
        <thead><tr><th>Name</th><th>Days</th><th>Window</th><th>State</th>
          <th>Description</th></tr></thead>
        <tbody>${scheds || '<tr><td colspan="5" class="muted">None defined.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Static Routes</h3>
      <table class="dt">
        <thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th>
          <th>Metric</th><th>Description</th></tr></thead>
        <tbody>${routes || '<tr><td colspan="5" class="muted">None defined.</td></tr>'}</tbody>
      </table>
    </div>
    ${shaping}`;

    wirePolicyButtons();
}

function wirePolicyButtons() {
    const nb = document.getElementById('alias-new');
    if (nb) nb.addEventListener('click', async () => {
        const name = prompt('Alias name (letters, digits, _ and - only):');
        if (!name) return;
        const kind = prompt('Kind — "network" or "port":', 'network');
        if (!kind) return;
        const entries = prompt(kind === 'port'
            ? 'Ports, comma separated (e.g. 80, 443, 8000-8100):'
            : 'Addresses or CIDRs, comma separated (e.g. 10.0.0.0/8):');
        if (!entries) return;
        try {
            await api('/api/aliases', { method: 'POST', body: { name, kind, entries } });
            toast(`Alias $${name} staged. Save a revision, then Apply.`);
            show('policy');
        } catch (e) { toast(e.message, true); }
    });

    document.querySelectorAll('[data-alias-edit]').forEach(b =>
        b.addEventListener('click', async () => {
            const name = b.dataset.aliasEdit;
            const entries = prompt(`Entries for $${name}:`, b.dataset.entries);
            if (entries === null) return;
            try {
                await api('/api/aliases/' + encodeURIComponent(name),
                          { method: 'PUT', body: { entries } });
                toast(`$${name} staged. Save a revision, then Apply.`);
                show('policy');
            } catch (e) { toast(e.message, true); }
        }));

    document.querySelectorAll('[data-alias-del]').forEach(b =>
        b.addEventListener('click', async () => {
            const name = b.dataset.aliasDel;
            if (!confirm(`Delete alias $${name}?`)) return;
            try {
                await api('/api/aliases/' + encodeURIComponent(name),
                          { method: 'DELETE' });
                toast(`$${name} deleted. Save a revision, then Apply.`);
                show('policy');
            } catch (e) { toast(e.message, true); }
        }));
}

/* ── VPN ───────────────────────────────────────────────────── */

function bytes(n) {
    if (!n) return '0';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(i ? 1 : 0) + ' ' + u[i];
}

async function renderVPN() {
    const d = await api('/api/vpn');

    const ifaces = d.wireguard.map(w => `
      <tr>
        <td class="mono"><b>${esc(w.ifname)}</b></td>
        <td>${w.enabled ? '<span class="ok">&#9679; enabled</span>'
                        : '<span class="muted">&#9679; disabled</span>'}</td>
        <td class="mono">${w.listen_port}/udp</td>
        <td class="mono">${esc(w.address)}/${w.cidr}</td>
        <td>${zoneChip(w.zone)}</td>
        <td class="mono small">${esc(w.public_key)}</td>
        <td class="mono small muted" title="SHA-256 prefix of the private key">${esc(w.key_fingerprint)}</td>
      </tr>`).join('');

    const peers = d.peers.map(p => `
      <tr>
        <td><b>${esc(p.name)}</b><div class="muted small">${esc(p.description)}</div></td>
        <td class="mono">${esc(p.interface)}</td>
        <td>${zoneChip(p.zone)}</td>
        <td class="mono small">${p.allowed_ips.map(esc).join('<br>')}</td>
        <td class="small">${p.roaming
            ? '<span class="muted">roaming</span>'
            : `<span class="mono">${esc(p.endpoint)}:${p.endpoint_port}</span>`}</td>
        <td>${p.has_psk ? '<span class="ok">&#10003;</span>'
                        : '<span class="muted">&mdash;</span>'}</td>
        <td class="mono small">${p.last_handshake
            ? new Date(p.last_handshake * 1000).toLocaleTimeString()
            : '<span class="muted">never</span>'}</td>
        <td class="mono small">${bytes(p.rx_bytes)} / ${bytes(p.tx_bytes)}</td>
        <td>${isAdmin()
            ? `<button class="mini" data-peer-del="${esc(p.name)}">Delete</button>`
            : '<span class="muted">&mdash;</span>'}</td>
      </tr>`).join('');

    const tunnels = d.ipsec.map(t => `
      <tr>
        <td><b>${esc(t.name)}</b><div class="muted small">${esc(t.description)}</div></td>
        <td>${t.enabled ? '<span class="ok">&#9679;</span>' : '<span class="muted">&#9679;</span>'}</td>
        <td class="mono">${esc(t.remote_host)}</td>
        <td class="mono small">${esc(t.local_subnet)}<br>&harr; ${esc(t.remote_subnet)}</td>
        <td>${esc(t.version)}</td>
        <td class="mono small">${esc(t.ike_proposal)}<br>${esc(t.esp_proposal)}</td>
        <td>${t.dpd ? '<span class="ok">&#10003;</span>' : '<span class="muted">&mdash;</span>'}</td>
        <td>${zoneChip(t.zone)}</td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>VPN</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi"><div class="kpi-n">${d.wireguard.length}</div><div class="kpi-l">WireGuard Links</div></div>
      <div class="kpi"><div class="kpi-n">${d.peers.length}</div><div class="kpi-l">Peers</div></div>
      <div class="kpi"><div class="kpi-n">${d.ipsec.length}</div><div class="kpi-l">IPsec Tunnels</div></div>
    </div>

    <div class="panel">
      <h3>WireGuard Interfaces</h3>
      <p class="muted small">The public key is what a peer configures at the far
         end. The private key never leaves this appliance; only a fingerprint
         of it is shown.</p>
      <table class="dt">
        <thead><tr><th>Interface</th><th>State</th><th>Port</th><th>Tunnel Address</th>
          <th>Zone</th><th>Public Key</th><th>Private Key</th></tr></thead>
        <tbody>${ifaces || '<tr><td colspan="7" class="muted">None configured.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Peers ${isAdmin()
        ? '<button class="mini primary" id="peer-new">Add peer</button>' +
          '<button class="mini" id="peer-keygen">Generate keypair</button>' : ''}</h3>
      <p class="muted small">A peer's zone decides which row of the forwarding
         matrix governs its traffic, so peers on one interface can be held to
         different policy.</p>
      <table class="dt">
        <thead><tr><th>Peer</th><th>Interface</th><th>Zone</th><th>Allowed IPs</th>
          <th>Endpoint</th><th>PSK</th><th>Handshake</th><th>RX / TX</th><th></th></tr></thead>
        <tbody>${peers || '<tr><td colspan="9" class="muted">No peers.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>IPsec Tunnels</h3>
      <p class="muted small">Site-to-site only. Pre-shared keys are stored but
         never shown here.</p>
      <table class="dt">
        <thead><tr><th>Tunnel</th><th>On</th><th>Remote</th><th>Subnets</th>
          <th>IKE</th><th>Proposals</th><th>DPD</th><th>Zone</th></tr></thead>
        <tbody>${tunnels || '<tr><td colspan="8" class="muted">None configured.</td></tr>'}</tbody>
      </table>
    </div>`;

    wireVPNButtons();
}

function wireVPNButtons() {
    const kg = document.getElementById('peer-keygen');
    if (kg) kg.addEventListener('click', async () => {
        try {
            const k = await api('/api/vpn/keygen', { method: 'POST' });
            /* Shown once and never stored: a prompt keeps it selectable so it
               can be copied straight into the peer's own configuration. */
            window.prompt(
                'Give the PUBLIC key to FireX when adding the peer, and the ' +
                'PRIVATE key to the peer itself. This is the only time the ' +
                'private key is shown.\n\nPublic:  ' + k.public_key +
                '\n\nPrivate (copy now):', k.private_key);
        } catch (e) { toast(e.message, true); }
    });

    const nb = document.getElementById('peer-new');
    if (nb) nb.addEventListener('click', async () => {
        const name = prompt('Peer name:');
        if (!name) return;
        const public_key = prompt("The peer's public key (44 characters):");
        if (!public_key) return;
        const allowed_ips = prompt(
            'Allowed IPs — what routes to this peer, comma separated\n' +
            '(e.g. 10.99.0.5/32, 192.168.60.0/24):');
        if (!allowed_ips) return;
        const zone = prompt('Zone for this peer (VPN, LAN, DMZ, GUEST…):', 'VPN');
        if (!zone) return;
        const endpoint = prompt(
            'Endpoint host:port, or leave empty for a roaming peer:', '');
        try {
            await api('/api/vpn/peers', {
                method: 'POST',
                body: { name, public_key, allowed_ips, zone,
                        endpoint: endpoint || undefined }
            });
            toast(`Peer ${name} staged. Save a revision, then Apply.`);
            show('vpn');
        } catch (e) { toast(e.message, true); }
    });

    document.querySelectorAll('[data-peer-del]').forEach(b =>
        b.addEventListener('click', async () => {
            const name = b.dataset.peerDel;
            if (!confirm(`Delete peer ${name}? It will lose access as soon as ` +
                         `the change is applied.`)) return;
            try {
                await api('/api/vpn/peers/' + encodeURIComponent(name),
                          { method: 'DELETE' });
                toast(`${name} deleted. Save a revision, then Apply.`);
                show('vpn');
            } catch (e) { toast(e.message, true); }
        }));
}

/* ── sparklines ────────────────────────────────────────────── */

/* A tiny inline SVG. Deliberately not a charting library: this has to render
   in a browser that may never have seen the internet. */
function spark(values, colour, height) {
    const h = height || 38, w = 240;
    if (!values.length) return `<svg width="${w}" height="${h}"></svg>`;

    const max = Math.max(1, ...values);
    const step = values.length > 1 ? w / (values.length - 1) : w;
    const pts = values.map((v, i) =>
        `${(i * step).toFixed(1)},${(h - (v / max) * (h - 4) - 2).toFixed(1)}`);

    return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"
                 preserveAspectRatio="none" role="img">
      <polyline points="${pts.join(' ')}" fill="none"
                stroke="${colour}" stroke-width="1.6"
                stroke-linejoin="round" stroke-linecap="round"/>
    </svg>`;
}

function sparkRow(label, values, colour, unit) {
    const last = values.length ? values[values.length - 1] : 0;
    const max  = values.length ? Math.max(...values) : 0;
    return `<tr>
      <td>${esc(label)}</td>
      <td class="sparkcell">${spark(values, colour)}</td>
      <td class="mono">${fmt(Math.round(last))}${unit || ''}</td>
      <td class="mono muted">${fmt(Math.round(max))}${unit || ''}</td>
    </tr>`;
}

async function renderMonitor() {
    const [h, t, ha] = await Promise.all([
        api('/api/history'), api('/api/telemetry'), haPanel()
    ]);
    const S = h.samples;

    const col = k => S.map(s => s[k] || 0);
    const span = S.length
        ? Math.round(S.length * h.interval / 60) + ' min'
        : 'no data yet';

    const rows = S.length ? [
        sparkRow('Packets / interval',  col('packets'),     '#4FC3F7'),
        sparkRow('Allowed',             col('allowed'),     '#00E58B'),
        sparkRow('Blocked',             col('blocked'),     '#FF3B5C'),
        sparkRow('Inter-VLAN allowed',  col('ivr_allowed'), '#00E58B'),
        sparkRow('Inter-VLAN denied',   col('ivr_denied'),  '#FF3B5C'),
        sparkRow('Block pages served',  col('pages'),       '#FFC247'),
        sparkRow('Off-hours skips',     col('sched_skipped'), '#B07CFF'),
        sparkRow('Tag violations',      col('tag_violations'), '#FF4B2B'),
        sparkRow('Tracked connections', col('states'),      '#7C9CFF'),
        sparkRow('WAN0 latency',        col('wan0_rtt'),    '#00D4D4', ' ms'),
        sparkRow('WAN1 latency',        col('wan1_rtt'),    '#7A879B', ' ms'),
        sparkRow('WAN0 loss',           col('wan0_loss'),   '#FF3B5C', '%')
    ].join('') : '';

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Monitor</h1>${roleBadge()}</div>

    ${ha}

    <div class="kpi-row">
      <div class="kpi"><div class="kpi-n">${S.length}</div>
        <div class="kpi-l">Samples (${esc(span)})</div></div>
      <div class="kpi"><div class="kpi-n">${h.interval}s</div>
        <div class="kpi-l">Sample Interval</div></div>
      <div class="kpi"><div class="kpi-n">${h.capacity}</div>
        <div class="kpi-l">Ring Capacity</div></div>
    </div>

    <div class="panel">
      <h3>Counters</h3>
      ${S.length ? `<table class="dt">
        <thead><tr><th>Series</th><th>Last ${esc(span)}</th>
          <th>Latest</th><th>Peak</th></tr></thead>
        <tbody>${rows}</tbody></table>`
      : `<p class="muted">Nothing sampled yet. The first sample establishes a
          baseline, so graphs start one interval (${h.interval}s) after
          startup.</p>`}
      <p class="muted small" style="margin-top:12px">
        History lives in memory and is lost on restart. Counters that only
        climb are shown as the change over each interval, so these are rates,
        not totals.</p>
    </div>

    <div class="panel">
      <h3>Export</h3>
      <table class="dt">
        <thead><tr><th>Exporter</th><th>Collector</th><th>State</th>
          <th>Sent</th><th>Dropped</th></tr></thead>
        <tbody>
          <tr>
            <td><b>Syslog</b> <span class="muted small">RFC 5424</span></td>
            <td class="mono">${t.syslog.configured
                ? esc(t.syslog.host) + ':' + t.syslog.port + '/' + esc(t.syslog.proto)
                : '<span class="muted">not configured</span>'}</td>
            <td>${!t.syslog.configured ? '<span class="muted">&mdash;</span>'
                 : t.syslog.connected ? '<span class="ok">&#9679; connected</span>'
                                      : '<span class="no">&#9679; unreachable</span>'}</td>
            <td class="mono">${fmt(t.syslog.sent)}</td>
            <td class="mono ${t.syslog.dropped ? 'danger' : 'muted'}">${fmt(t.syslog.dropped)}</td>
          </tr>
          <tr>
            <td><b>NetFlow</b> <span class="muted small">v5</span></td>
            <td class="mono">${t.netflow.configured
                ? esc(t.netflow.host) + ':' + t.netflow.port
                : '<span class="muted">not configured</span>'}</td>
            <td>${!t.netflow.configured ? '<span class="muted">&mdash;</span>'
                 : t.netflow.connected ? '<span class="ok">&#9679; connected</span>'
                                       : '<span class="no">&#9679; unreachable</span>'}</td>
            <td class="mono">${fmt(t.netflow.flows)} flows
                <span class="muted small">in ${fmt(t.netflow.packets)} datagrams</span></td>
            <td class="muted">&mdash;</td>
          </tr>
        </tbody>
      </table>
      ${t.netflow.configured ? `<p class="muted small" style="margin-top:12px">
        Flows are exported every ${t.netflow.interval}s from the kernel
        connection table.</p>` : ''}
    </div>`;

    wireHaButtons();
}

/* ── diagnostics: state table and packet capture ───────────── */

async function renderDiagnostics() {
    const [st, cap] = await Promise.all([api('/api/state'), api('/api/capture')]);

    const usage = st.max ? Math.round((st.count / st.max) * 100) : 0;

    const rows = st.entries.map(e => `
      <tr>
        <td class="mono">${esc(e.proto)}</td>
        <td class="mono">${esc(e.src)}:${e.sport}</td>
        <td class="mono">${esc(e.dst)}:${e.dport}</td>
        <td>${esc(e.state)}${e.assured
            ? ' <span class="ok small">assured</span>' : ''}</td>
        <td class="mono small">${fmt(e.packets)} / ${fmt(e.bytes)}</td>
        <td class="mono small">${fmt(e.rx_packets)} / ${fmt(e.rx_bytes)}</td>
        <td class="mono">${e.ttl}s</td>
      </tr>`).join('');

    const running = cap.state === 'running';

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Diagnostics</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi ${usage > 80 ? 'danger' : ''}">
        <div class="kpi-n">${fmt(st.count)}</div><div class="kpi-l">Tracked Connections</div></div>
      <div class="kpi"><div class="kpi-n">${fmt(st.max)}</div><div class="kpi-l">Table Capacity</div></div>
      <div class="kpi ${usage > 80 ? 'warn' : ''}">
        <div class="kpi-n">${usage}%</div><div class="kpi-l">Used</div></div>
      <div class="kpi"><div class="kpi-n">${st.listed}</div><div class="kpi-l">Listed Below</div></div>
    </div>

    <div class="panel">
      <h3>Packet Capture</h3>
      ${isAdmin() ? `
      <div class="capform">
        <label>Interface<input id="cap-if" placeholder="eth1" value="${esc(cap.iface || '')}"></label>
        <label>Host <span class="muted">(optional)</span><input id="cap-host" placeholder="any"></label>
        <label>Port <span class="muted">(optional)</span><input id="cap-port" placeholder="any"></label>
        <label>Protocol<select id="cap-proto">
          <option value="any">any</option><option value="tcp">tcp</option>
          <option value="udp">udp</option><option value="icmp">icmp</option>
        </select></label>
        <label>Max packets<input id="cap-pkts" value="${cap.max_packets || 1000}"></label>
        <label>Max seconds<input id="cap-secs" value="${cap.max_seconds || 30}"></label>
        <button class="mini ${running ? '' : 'primary'}" id="cap-go"
                ${running ? 'disabled' : ''}>Start capture</button>
        <button class="mini warn" id="cap-stop" ${running ? '' : 'disabled'}>Stop</button>
      </div>` : '<p class="muted small">Captures can only be started by an admin.</p>'}

      <table class="dt" style="margin-top:14px">
        <tbody>
          <tr><td>State</td><td><b class="${
            cap.state === 'running' ? 'warn' :
            cap.state === 'failed'  ? 'no'   :
            cap.state === 'done'    ? 'ok'   : 'muted'}">${esc(cap.state)}</b>
            ${cap.error ? ' <span class="no small">' + esc(cap.error) + '</span>' : ''}</td></tr>
          <tr><td>Captured</td><td class="mono">${fmt(cap.packets)} packet(s)
            of ${fmt(cap.seen)} seen, ${fmt(cap.bytes)} bytes</td></tr>
          <tr><td>Download</td><td>${cap.downloadable
            ? '<a class="mini" href="/api/capture/download" download="firex-capture.pcap">firex-capture.pcap</a>'
            : '<span class="muted">nothing to download yet</span>'}</td></tr>
        </tbody>
      </table>
      <p class="muted small" style="margin-top:12px">
        Every capture is bounded by packets, seconds and size at once &mdash; at
        most ${fmt(cap.caps.packets)} packets, ${cap.caps.seconds}s or
        ${Math.round(cap.caps.bytes / 1048576)} MB, whichever arrives first.
        Filtering is by interface, host, port and protocol; this build does not
        link libpcap, so tcpdump expression syntax is not available.</p>
    </div>

    <div class="panel">
      <h3>Connection Table <span class="muted small">via ${esc(st.source)}</span></h3>
      ${st.source === 'unavailable'
        ? `<p class="muted">${esc(st.detail)}</p>`
        : `<table class="dt">
            <thead><tr><th>Proto</th><th>Source</th><th>Destination</th>
              <th>State</th><th>Out pkts / bytes</th><th>In pkts / bytes</th>
              <th>Expires</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="7" class="muted">No connections.</td></tr>'}</tbody>
          </table>`}
    </div>`;

    wireCaptureButtons();
}

function wireCaptureButtons() {
    const go = document.getElementById('cap-go');
    if (go) go.addEventListener('click', async () => {
        const body = {
            iface:       document.getElementById('cap-if').value.trim(),
            proto:       document.getElementById('cap-proto').value,
            max_packets: Number(document.getElementById('cap-pkts').value) || 0,
            max_seconds: Number(document.getElementById('cap-secs').value) || 0
        };
        const host = document.getElementById('cap-host').value.trim();
        const port = Number(document.getElementById('cap-port').value) || 0;
        if (host) body.host = host;
        if (port) body.port = port;

        if (!body.iface) { toast('An interface is required', true); return; }
        try {
            await api('/api/capture/start', { method: 'POST', body });
            toast('Capture started');
            show('diagnostics');
        } catch (e) { toast(e.message, true); }
    });

    const stop = document.getElementById('cap-stop');
    if (stop) stop.addEventListener('click', async () => {
        try {
            await api('/api/capture/stop', { method: 'POST' });
            toast('Capture stopped');
            show('diagnostics');
        } catch (e) { toast(e.message, true); }
    });
}

/* ── captive portal ────────────────────────────────────────── */

function mins(sec) {
    const m = Math.round(sec / 60);
    return m < 60 ? m + ' min' : (m / 60).toFixed(1) + ' h';
}

async function renderPortal() {
    const d = await api('/api/portal');
    const now = Math.floor(Date.now() / 1000);

    const sessions = d.sessions.map(s => `
      <tr>
        <td class="mono"><b>${esc(s.ip)}</b></td>
        <td>${esc(s.user)}</td>
        <td class="mono">${s.vlan_id || '<span class="muted">&mdash;</span>'}</td>
        <td class="small">${new Date(s.started * 1000).toLocaleTimeString()}</td>
        <td class="small">${s.expires > now
            ? mins(s.expires - now) + ' left'
            : '<span class="no">expired</span>'}</td>
        <td class="mono small">${esc(s.voucher) || '<span class="muted">&mdash;</span>'}</td>
        <td>${isAdmin()
            ? `<button class="mini" data-kick="${esc(s.ip)}">Disconnect</button>`
            : '<span class="muted">&mdash;</span>'}</td>
      </tr>`).join('');

    const vouchers = d.vouchers.map(v => `
      <tr>
        <td class="mono"><b>${esc(v.code)}</b></td>
        <td class="mono">${mins(v.minutes * 60)}</td>
        <td>${!v.enabled ? '<span class="no">revoked</span>'
             : v.used    ? '<span class="warn">in use</span>'
                         : '<span class="ok">unused</span>'}</td>
        <td class="small">${v.first_used
            ? new Date(v.first_used * 1000).toLocaleString()
            : '<span class="muted">not yet redeemed</span>'}</td>
        <td class="small">${esc(v.note)}</td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Captive Portal</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi ${d.enabled ? 'ok' : ''}">
        <div class="kpi-n">${d.enabled ? esc(d.auth) : 'off'}</div>
        <div class="kpi-l">Authentication</div></div>
      <div class="kpi"><div class="kpi-n">${d.sessions.length}</div>
        <div class="kpi-l">Active Sessions</div></div>
      <div class="kpi ok"><div class="kpi-n">${fmt(d.stats.ok)}</div>
        <div class="kpi-l">Successful Logins</div></div>
      <div class="kpi ${d.stats.failed ? 'danger' : ''}">
        <div class="kpi-n">${fmt(d.stats.failed)}</div>
        <div class="kpi-l">Rejected</div></div>
      <div class="kpi"><div class="kpi-n">${fmt(d.stats.expired)}</div>
        <div class="kpi-l">Expired</div></div>
    </div>

    ${!d.enabled ? `<div class="panel"><p class="muted">
      The portal is disabled. Clients on captive VLANs are not intercepted.
      </p></div>` : ''}

    <div class="panel">
      <h3>Active Sessions</h3>
      <p class="muted small">Sessions last ${d.session_minutes} minutes, or
         ${d.idle_minutes} minutes without traffic, whichever comes first.
         ${d.radius.configured
           ? 'Credentials are checked against ' + esc(d.radius.host) + ':' +
             d.radius.port + '.' : ''}</p>
      <table class="dt">
        <thead><tr><th>Address</th><th>Signed in as</th><th>VLAN</th>
          <th>Since</th><th>Remaining</th><th>Voucher</th><th></th></tr></thead>
        <tbody>${sessions || '<tr><td colspan="7" class="muted">Nobody is signed in.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Vouchers ${isAdmin()
        ? '<button class="mini primary" id="v-new">Generate</button>' : ''}</h3>
      <p class="muted small">A voucher's clock starts when it is first
         redeemed, not when it is created, and the same code can be used by
         more than one device inside its window.</p>
      <table class="dt">
        <thead><tr><th>Code</th><th>Good for</th><th>State</th>
          <th>First redeemed</th><th>Note</th></tr></thead>
        <tbody>${vouchers || '<tr><td colspan="5" class="muted">None generated.</td></tr>'}</tbody>
      </table>
    </div>`;

    wirePortalButtons();
}

function wirePortalButtons() {
    const nv = document.getElementById('v-new');
    if (nv) nv.addEventListener('click', async () => {
        const count = Number(prompt('How many vouchers?', '10'));
        if (!count) return;
        const minutes = Number(prompt('Valid for how many minutes once redeemed?', '1440'));
        if (!minutes) return;
        const note = prompt('Note (e.g. who they are for):', '') || '';
        try {
            const r = await api('/api/portal/vouchers',
                                { method: 'POST', body: { count, minutes, note } });
            toast(`${r.count} voucher(s) generated`);
            show('portal');
        } catch (e) { toast(e.message, true); }
    });

    document.querySelectorAll('[data-kick]').forEach(b =>
        b.addEventListener('click', async () => {
            const who = b.dataset.kick;
            if (!confirm(`Disconnect ${who}? They will have to sign in again.`)) return;
            try {
                await api('/api/portal/sessions/' + encodeURIComponent(who),
                          { method: 'DELETE' });
                toast(`${who} disconnected`);
                show('portal');
            } catch (e) { toast(e.message, true); }
        }));
}

/* ── shaping, shown inside the Policy view ─────────────────── */

async function shapingPanel() {
    let d;
    try { d = await api('/api/shaping'); } catch (e) { return ''; }

    const rows = d.vlans.map(v => `
      <tr>
        <td class="mono"><b>${v.vlan_id}</b></td>
        <td>${esc(v.name)}</td>
        <td class="mono">${v.up_mbps ? v.up_mbps + ' Mbit'
            : '<span class="muted">share</span>'}</td>
        <td class="mono">${v.down_mbps ? v.down_mbps + ' Mbit'
            : '<span class="muted">unlimited</span>'}</td>
        <td class="mono">${v.priority}</td>
        <td class="mono small">1:${v.classid}</td>
      </tr>`).join('');

    return `
    <div class="panel">
      <h3>Traffic Shaping
        <span class="muted small">${d.enabled
          ? esc(d.qdisc) + (d.applied ? ', applied' : ', not yet applied')
          : 'disabled'}</span></h3>
      ${d.error ? `<p class="no small">${esc(d.error)}</p>` : ''}
      ${!d.enabled ? '<p class="muted">Shaping is off; bandwidth limits below do nothing.</p>' : `
      <p class="muted small">HTB enforces the ceilings;
         ${esc(d.qdisc)}${d.qdisc === 'fq_codel'
           ? ` (target ${d.codel_target_ms}ms, interval ${d.codel_interval_ms}ms${d.ecn ? ', ECN' : ''})`
           : ''} underneath is what keeps the link responsive while it is
         saturated. Upload ceiling ${d.wan_up_mbps || '&mdash;'} Mbit;
         download ${d.ingress_shaping
           ? d.wan_down_mbps + ' Mbit via IFB' : 'not shaped on ingress'}.</p>`}
      <table class="dt">
        <thead><tr><th>VID</th><th>Name</th><th>Upload</th><th>Download</th>
          <th>802.1p</th><th>Class</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">No VLAN has bandwidth limits.</td></tr>'}</tbody>
      </table>
      <details style="margin-top:14px">
        <summary class="muted small" style="cursor:pointer">
          Show the ${d.plan_count} tc commands this configuration produces</summary>
        <pre class="planbox">${d.plan.map(esc).join('\n')}</pre>
      </details>
    </div>`;
}

/* ── high availability ─────────────────────────────────────── */

async function haPanel() {
    let h;
    try { h = await api('/api/ha'); } catch (e) { return ''; }
    if (!h.enabled) return '';

    const stateCls = h.state === 'MASTER' ? 'ok'
                   : h.state === 'BACKUP' ? 'muted'
                   : h.state === 'FAULT'  ? 'no' : 'warn';

    const since = h.state_since
        ? new Date(h.state_since * 1000).toLocaleString() : '—';

    return `
    <div class="panel">
      <h3>High Availability
        <span class="muted small">${esc(h.role)}, VRID ${h.vrrp_id}</span></h3>
      ${h.error ? `<p class="no small">${esc(h.error)}</p>` : ''}

      <div class="kpi-row" style="margin-bottom:16px">
        <div class="kpi ${h.state === 'MASTER' ? 'ok' : ''}">
          <div class="kpi-n ${stateCls}">${esc(h.state)}</div>
          <div class="kpi-l">${h.state === 'MASTER'
              ? 'This Node Carries Traffic' : 'VRRP State'}</div></div>
        <div class="kpi"><div class="kpi-n">${h.vips}</div>
          <div class="kpi-l">Virtual Addresses</div></div>
        <div class="kpi"><div class="kpi-n">${h.priority}</div>
          <div class="kpi-l">Priority</div></div>
        <div class="kpi ${h.transitions > 2 ? 'warn' : ''}">
          <div class="kpi-n">${fmt(h.transitions)}</div>
          <div class="kpi-l">Transitions</div></div>
      </div>

      <table class="dt">
        <tbody>
          <tr><td>Peer</td><td class="mono">${esc(h.peer) || '<span class="muted">—</span>'}</td></tr>
          <tr><td>Sync link</td><td class="mono">${esc(h.sync_interface) || '<span class="muted">—</span>'}</td></tr>
          <tr><td>In this state since</td><td class="small">${esc(since)}</td></tr>
          <tr><td>Preempt</td><td>${h.preempt
            ? '<span class="ok">&#10003;</span> reclaims when the primary returns'
            : '<span class="muted">&mdash;</span> stays where it is'}</td></tr>
          <tr><td>Connection sync</td><td>${h.conntrack_sync
            ? '<span class="ok">&#10003;</span> established connections survive a failover'
            : '<span class="warn">&#10007;</span> connections reset on failover'}</td></tr>
          <tr><td>Config replication</td><td>${h.config_sync
            ? `<span class="ok">&#10003;</span> sent ${fmt(h.pushes.sent)}, received ${fmt(h.pushes.received)}` +
              (h.pushes.rejected ? `, <span class="danger">${fmt(h.pushes.rejected)} rejected</span>` : '')
            : '<span class="warn">&#10007;</span> the nodes can drift apart'}</td></tr>
        </tbody>
      </table>

      ${isAdmin() && h.config_sync && h.role === 'primary'
        ? '<button class="mini primary" id="ha-push" style="margin-top:14px">Push config to peer</button>'
        : ''}
      ${!h.applied ? `<p class="muted small" style="margin-top:12px">
        Not yet applied. The configuration is generated but keepalived has not
        been started from it.</p>` : ''}
    </div>`;
}

function wireHaButtons() {
    const b = document.getElementById('ha-push');
    if (!b) return;
    b.addEventListener('click', async () => {
        if (!confirm('Push this node’s configuration to the peer? ' +
                     'It will replace what the peer is running.')) return;
        b.disabled = true;
        try {
            await api('/api/ha/push', { method: 'POST' });
            toast('Configuration pushed to the peer');
            show('monitor');
        } catch (e) { toast(e.message, true); b.disabled = false; }
    });
}

/* ── threat layer ──────────────────────────────────────────── */

const CLASS_COLOURS = {
    malware:'#FF3B5C', c2:'#FF4B2B', exploit:'#FFC247',
    recon:'#4FC3F7', dos:'#B07CFF', policy:'#7A879B'
};

function classChip(c) {
    return `<span class="zone-chip" style="--zc:${CLASS_COLOURS[c] || '#888'}">${esc(c)}</span>`;
}

function sevDot(n) {
    const cls = n >= 4 ? 'danger' : n === 3 ? 'warn' : n === 2 ? 'ok' : 'muted';
    return `<span class="sev s${n}">${n}</span><span class="${cls}"></span>`;
}

async function renderThreat() {
    const d = await api('/api/threat');
    const r = d.response, b = d.blocklist;

    const sigs = d.top.map(s => `
      <tr>
        <td class="mono">${s.sid}</td>
        <td>${esc(s.msg)}</td>
        <td>${classChip(s.class)}</td>
        <td>${sevDot(s.severity)}</td>
        <td><span class="${s.action === 'alert' ? 'muted' : 'danger'}">${esc(s.action)}</span></td>
        <td class="mono">${fmt(s.hits)}</td>
        <td class="small">${s.last_hit
            ? new Date(s.last_hit * 1000).toLocaleTimeString() : '—'}</td>
      </tr>`).join('');

    const feeds = d.feeds.map(f => `
      <tr>
        <td><b>${esc(f.name)}</b></td>
        <td>${esc(f.kind)}</td>
        <td class="mono small">${esc(f.url)}</td>
        <td class="mono">${fmt(f.entries)}</td>
        <td class="small">${f.last_fetch
            ? new Date(f.last_fetch * 1000).toLocaleTimeString()
            : '<span class="muted">never</span>'}</td>
        <td class="small">${f.error
            ? '<span class="no">' + esc(f.error) + '</span>'
            : '<span class="ok">&#10003;</span>'}</td>
      </tr>`).join('');

    const offenders = r.offenders.map(o => `
      <tr>
        <td class="mono"><b>${esc(o.ip)}</b></td>
        <td class="mono ${o.score >= r.threshold ? 'danger' : ''}">${o.score}
          <span class="muted small">/ ${r.threshold}</span></td>
        <td class="mono">${o.detections}</td>
        <td>${o.blocked
            ? `<span class="no">&#9679; ${Math.ceil(o.remaining / 60)} min left</span>`
            : '<span class="muted">&#9679; watching</span>'}</td>
        <td class="mono">${o.block_count}</td>
        <td class="small">${esc(o.reason)}</td>
        <td>${isAdmin()
            ? `<button class="mini" data-release="${esc(o.ip)}">Release</button>`
            : '<span class="muted">—</span>'}</td>
      </tr>`).join('');

    const rate = d.scanned ? ((d.matched / d.scanned) * 100).toFixed(1) : '0.0';

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Threat</h1>${roleBadge()}</div>

    <div class="kpi-row">
      <div class="kpi ${d.enabled ? 'ok' : ''}">
        <div class="kpi-n">${d.signatures}</div><div class="kpi-l">Signatures</div></div>
      <div class="kpi"><div class="kpi-n">${fmt(d.scanned)}</div>
        <div class="kpi-l">Payloads Scanned</div></div>
      <div class="kpi ${d.matched ? 'warn' : ''}">
        <div class="kpi-n">${fmt(d.matched)}</div>
        <div class="kpi-l">Matched (${rate}%)</div></div>
      <div class="kpi ${d.dropped ? 'danger' : ''}">
        <div class="kpi-n">${fmt(d.dropped)}</div><div class="kpi-l">Dropped</div></div>
      <div class="kpi ${r.offenders.filter(o => o.blocked).length ? 'danger' : ''}">
        <div class="kpi-n">${r.offenders.filter(o => o.blocked).length}</div>
        <div class="kpi-l">Hosts Held</div></div>
    </div>

    ${!d.enabled ? '<div class="panel"><p class="muted">The threat layer is disabled.</p></div>' : ''}
    ${d.enabled && !d.inline ? `<div class="panel">
      <p class="warn"><b>Alert-only.</b> Rules that say drop are reporting and
      letting traffic through. Turn on <span class="mono">inline</span> in
      <span class="mono">[threat]</span> once you trust the ruleset.</p>
    </div>` : ''}

    <div class="panel">
      <h3>Signatures That Fired
        <span class="muted small">${d.states} automaton states</span></h3>
      <p class="muted small">Every pattern is matched in one pass over the
         payload, so the cost does not grow with the rule count. Matching is
         within a single packet: there is no stream reassembly, so a pattern
         split across two segments is missed.</p>
      <table class="dt">
        <thead><tr><th>SID</th><th>Signature</th><th>Class</th><th>Sev</th>
          <th>Action</th><th>Hits</th><th>Last</th></tr></thead>
        <tbody>${sigs || '<tr><td colspan="7" class="muted">Nothing has matched yet.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Blocklists ${isAdmin()
        ? '<button class="mini" id="feed-refresh">Refresh now</button>' : ''}</h3>
      <p class="muted small">${fmt(b.ranges)} merged address range(s) and
         ${fmt(b.domains)} domain(s), ${fmt(b.lookups)} lookups,
         ${fmt(b.ip_hits)} address hits and ${fmt(b.domain_hits)} domain hits.
         A failed fetch keeps the previous list rather than emptying it.</p>
      <table class="dt">
        <thead><tr><th>Feed</th><th>Kind</th><th>Source</th><th>Entries</th>
          <th>Last fetch</th><th>State</th></tr></thead>
        <tbody>${feeds || '<tr><td colspan="6" class="muted">No feeds configured.</td></tr>'}</tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Automatic Response
        <span class="muted small">${r.enabled
          ? (r.quarantine ? 'quarantine' : 'block') + ' at score ' + r.threshold
          : 'disabled'}</span></h3>
      <p class="muted small">Detections accumulate a score rather than
         blocking on the first hit; a host decays back to nothing while quiet,
         and is held longer each time it returns.
         ${fmt(r.blocks)} block(s), ${fmt(r.releases)} release(s),
         ${fmt(r.escalations)} escalation(s).
         ${r.quarantine ? 'A quarantined host is evaluated as the QUARANTINE ' +
           'zone, so the forwarding matrix decides what it may still reach.' : ''}</p>
      <table class="dt">
        <thead><tr><th>Address</th><th>Score</th><th>Detections</th>
          <th>State</th><th>Times held</th><th>Last detection</th><th></th></tr></thead>
        <tbody>${offenders || '<tr><td colspan="7" class="muted">No hosts under watch.</td></tr>'}</tbody>
      </table>
    </div>`;

    wireThreatButtons();
}

function wireThreatButtons() {
    const rf = document.getElementById('feed-refresh');
    if (rf) rf.addEventListener('click', async () => {
        rf.disabled = true;
        try {
            const r = await api('/api/threat/feeds/refresh', { method: 'POST' });
            toast(`${r.feeds} feed(s) refreshed`);
            show('threat');
        } catch (e) { toast(e.message, true); rf.disabled = false; }
    });

    document.querySelectorAll('[data-release]').forEach(b =>
        b.addEventListener('click', async () => {
            const who = b.dataset.release;
            if (!confirm(`Release ${who}? Its score and history are cleared.`)) return;
            try {
                await api('/api/threat/offenders/' + encodeURIComponent(who),
                          { method: 'DELETE' });
                toast(`${who} released`);
                show('threat');
            } catch (e) { toast(e.message, true); }
        }));
}

function roleBadge() {
    if (!state.role) return '';
    return isAdmin()
        ? `<span class="role-badge admin" title="Signed in as ${esc(state.user)}">ADMIN</span>`
        : `<span class="ro-badge" title="Signed in as ${esc(state.user)}">READ&nbsp;ONLY</span>`;
}

/* ── revisions ─────────────────────────────────────────────── */

async function renderRevisions() {
    const d = await api('/api/config/revisions');
    const rows = d.revisions.map(r => `
      <tr>
        <td class="mono"><b>${r.revision}</b></td>
        <td class="small">${new Date(r.time * 1000).toLocaleString()}</td>
        <td>${esc(r.author)}</td>
        <td class="small">${esc(r.note)}</td>
        <td>${isAdmin() && r.revision !== d.latest
              ? `<button class="mini" data-rollback="${r.revision}">Roll back</button>`
              : '<span class="muted">&mdash;</span>'}</td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
    <div class="page-head"><h1>Configuration History</h1>${roleBadge()}</div>
    <div class="panel">
      <h3>Saved Revisions <span class="muted small">(latest: ${d.latest})</span></h3>
      <table class="dt">
        <thead><tr><th>Rev</th><th>When</th><th>By</th><th>Note</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="muted">No revisions yet.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="panel">
      <h3>Backup</h3>
      <p class="muted small">Downloads the configuration that is active right now.</p>
      <a class="mini" href="/api/config/backup" download="firex.conf">Download firex.conf</a>
    </div>`;

    document.querySelectorAll('[data-rollback]').forEach(b =>
        b.addEventListener('click', async () => {
            const rev = Number(b.dataset.rollback);
            if (!confirm(`Roll back to revision ${rev}? The appliance will ` +
                         `re-provision its network immediately.`)) return;
            b.disabled = true;
            try {
                const r = await api('/api/config/rollback',
                                    { method: 'POST', body: { revision: rev } });
                toast(`Rolled back to ${rev} (now revision ${r.revision})`);
                show('revisions');
            } catch (e) { toast(e.message, true); b.disabled = false; }
        }));
}

/* ── config actions ────────────────────────────────────────── */

function configBar() {
    const bar = document.getElementById('configbar');
    if (!bar) return;
    if (!isAdmin()) { bar.innerHTML = ''; return; }
    bar.innerHTML = `
      <button class="mini" id="btn-validate">Validate</button>
      <button class="mini primary" id="btn-save">Save revision</button>
      <button class="mini warn" id="btn-apply">Apply</button>`;

    document.getElementById('btn-validate').addEventListener('click', async () => {
        try {
            const d = await api('/api/config/validate');
            toast(d.warnings ? `Valid, ${d.warnings} warning(s): ${d.warning}`
                             : 'Active configuration is valid');
        } catch (e) { toast(e.message, true); }
    });

    document.getElementById('btn-save').addEventListener('click', async () => {
        const note = prompt('Describe this change (optional):', '');
        if (note === null) return;
        try {
            const d = await api('/api/config/save',
                                { method: 'POST', body: { note } });
            toast(`Saved as revision ${d.revision}`);
        } catch (e) { toast(e.message, true); }
    });

    document.getElementById('btn-apply').addEventListener('click', async () => {
        if (!confirm('Apply the saved configuration? VLAN interfaces and ' +
                     'firewall rules will be rebuilt. A failed apply rolls ' +
                     'back automatically.')) return;
        try {
            await api('/api/config/apply', { method: 'POST' });
            toast('Configuration applied');
            show(current);
        } catch (e) { toast(e.message, true); }
    });
}

const CYCLE = ['ALLOW', 'LOG_ALLOW', 'LOG_DENY', 'DENY'];

function wireMatrix() {
    document.querySelectorAll('td.editable').forEach(td =>
        td.addEventListener('click', async () => {
            const next = CYCLE[(CYCLE.indexOf(td.dataset.act) + 1) % CYCLE.length];
            try {
                await api('/api/zones/matrix', {
                    method: 'POST',
                    body: { from: td.dataset.from, to: td.dataset.to, action: next }
                });
                toast(`${td.dataset.from} -> ${td.dataset.to}: ${next}. ` +
                      `Save a revision, then Apply.`);
                show('vlans');
            } catch (e) { toast(e.message, true); }
        }));
}

/* ── login ─────────────────────────────────────────────────── */

function renderLogin(msg) {
    document.getElementById('configbar').innerHTML = '';
    document.getElementById('content').innerHTML = `
    <div class="login-wrap">
      <form class="login" id="loginform">
        <h2>Sign in</h2>
        <p class="muted small">This console manages live network segmentation.</p>
        <label>Username<input name="username" autocomplete="username" autofocus required></label>
        <label>Password<input name="password" type="password"
               autocomplete="current-password" required></label>
        <button type="submit" class="primary">Sign in</button>
        <p class="no small" id="loginerr">${msg ? esc(msg) : ''}</p>
      </form>
    </div>`;

    document.getElementById('loginform').addEventListener('submit', async ev => {
        ev.preventDefault();
        const f = new FormData(ev.target);
        const btn = ev.target.querySelector('button');
        btn.disabled = true;
        try {
            const d = await api('/api/auth/login', {
                method: 'POST',
                body: { username: f.get('username'), password: f.get('password') }
            });
            state.user = d.user; state.role = d.role; state.csrf = d.csrf;
            chrome(true);
            show('monitor');
        } catch (e) {
            document.getElementById('loginerr').textContent = e.message;
            btn.disabled = false;
        }
    });
}

/* ══════════════════════════════════════════════════════════════════════
 *  Shell: navigation, page headings and the status strip
 *
 *  The nav is built from this table rather than written into the HTML, so
 *  a page cannot exist without a heading and a description, and the order
 *  on screen is the order an operator works in: what is happening, then
 *  the network, then what is defending it, then the box itself.
 * ══════════════════════════════════════════════════════════════════════ */

const NAV = [
    ['Monitor', [
        ['monitor',     'Dashboard',    'i-dash',    'Throughput, sessions and the state of the engine'],
        ['events',      'Events',       'i-events',  'What the appliance blocked, and why'],
        ['diagnostics', 'Diagnostics',  'i-diag',    'Captures, connectivity and live counters']
    ]],
    ['Network', [
        ['interfaces',  'Interfaces',   'i-port',    'Physical ports and logical links, as the kernel sees them'],
        ['vlans',       'Segmentation', 'i-seg',     'VLANs, port assignments and the zone forwarding matrix'],
        ['wan',         'WAN',          'i-wan',     'Uplinks, failover and port forwards'],
        ['vpn',         'VPN',          'i-vpn',     'WireGuard peers and IPsec tunnels']
    ]],
    ['Security', [
        ['malware',     'Malware',      'i-malware', 'Live scanning of transfers that cross the appliance'],
        ['airgap',      'Air gap',      'i-airgap',  'Isolation of the untrusted boundary'],
        ['threat',      'Threat',       'i-threat',  'Signatures, reputation feeds and quarantined hosts'],
        ['policy',      'Policy',       'i-policy',  'Aliases and time-based rules'],
        ['portal',      'Portal',       'i-portal',  'Captive portal sessions and vouchers']
    ]],
    ['Appliance', [
        ['revisions',   'Configuration','i-config',  'Saved revisions, backup and rollback'],
        ['audit',       'Audit',        'i-audit',   'Who changed what on this appliance, and from where'],
        ['accounts',    'System',       'i-system',  'Accounts, passwords and appliance identity']
    ]]
];

const PAGE = {};
NAV.forEach(([, items]) => items.forEach(([id, label, icon, sub]) =>
    PAGE[id] = { label, icon, sub }));

function buildNav() {
    const nav = document.getElementById('nav');
    if (!nav) return;
    nav.innerHTML = NAV.map(([group, items]) =>
        `<div class="nav-group">${esc(group)}</div>` +
        items.map(([id, label, icon]) =>
            `<button class="navbtn" data-view="${id}">
               <svg viewBox="0 0 24 24"><use href="#${icon}"/></svg>
               <span>${esc(label)}</span>
               <span class="nav-tag" data-tag="${id}"></span>
             </button>`).join('')
    ).join('');

    nav.querySelectorAll('.navbtn').forEach(b =>
        b.addEventListener('click', () => {
            show(b.dataset.view);
            document.getElementById('side').classList.remove('open');
        }));
}

/* Show or hide the parts of the shell that only make sense when signed in. */
function chrome(on) {
    /* display, not visibility: a hidden sidebar that still reserves its
     * column leaves the sign-in card pushed off-centre with an empty
     * strip beside it, which reads as a rendering fault. */
    const side = document.getElementById('side');
    if (side) side.style.display = on ? '' : 'none';
    const who = document.getElementById('whoami');
    if (who) who.textContent = on ? `${state.user} (${state.role})` : '';
    const out = document.getElementById('btn-logout');
    if (out) out.style.display = on ? '' : 'none';
    const sys = document.getElementById('sysbar');
    if (sys && !on) sys.innerHTML = '';
    configBar();
}

/*
 * The strip along the top. Four facts, chosen because each one is a thing
 * an operator would otherwise have to change page to find out, and each
 * can be wrong in a way that matters.
 */
function uptimeText(sec) {
    sec = Math.max(0, sec | 0);
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600),
          m = Math.floor(sec % 3600 / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
}

async function sysbar() {
    const el = document.getElementById('sysbar');
    if (!el || !state.csrf) return;
    try {
        const sys = await api('/api/system');
        const v = document.getElementById('sf-version');
        const u = document.getElementById('sf-uptime');
        if (v) v.textContent = sys.version || '';
        if (u) u.textContent = uptimeText(sys.uptime);

        /* The product and vendor names live in brand.h and reach the page
         * from here, so a re-skin is one file and this one needs no edit. */
        const bp = document.getElementById('brand-product');
        const bv = document.getElementById('brand-vendor');
        if (bp && sys.product) bp.textContent = sys.product;
        if (bv && sys.vendor)  bv.textContent = 'by ' + sys.vendor;
        if (sys.product && sys.vendor)
            document.title = `${sys.product} Console`;

        /*
         * Two pieces of state the operator cannot get any other way.
         *
         * The transport, because a management page gives no sign of how it
         * arrived and "it is on 8443" was true for the whole period this
         * console served in the clear.
         *
         * And whether anything is unsaved, because the console applies a
         * change at once and writes it only on Save -- so an operator who
         * isolates the appliance and reboots finds it connected again,
         * with nothing having warned them.
         */
        const tl = document.getElementById('tls-state');
        if (tl) {
            tl.className = 'conn ' + (sys.tls ? 'ok' : 'bad');
            tl.textContent = sys.tls ? 'Encrypted' : 'NOT ENCRYPTED';
            tl.title = sys.tls
                ? 'TLS, certificate SHA-256 ' + (sys.tls_fingerprint || '')
                : 'This console is served over plain HTTP. Credentials and '
                  + 'the session cookie cross the management network in the clear.';
        }

        const ub = document.getElementById('unsaved');
        if (ub) {
            ub.style.display = sys.unsaved ? '' : 'none';
            ub.textContent   = sys.unsaved === 1
                ? '1 unsaved change'
                : `${sys.unsaved} unsaved changes`;
            ub.title = 'In effect now, but not in the configuration file. '
                     + 'Save a revision or the appliance reverts on restart.';
        }
    } catch (e) { /* the footer is decoration; a failure here is not news */ }

    try {
        const [vl, ag, mw, th] = await Promise.all([
            api('/api/vlans'), api('/api/airgap'),
            api('/api/malware'), api('/api/threat')
        ]);

        const st  = vl.stats || {};
        const gap = ag.mode !== 'connected';

        el.innerHTML = `
          <div class="sys-item"><span class="v ok">${fmt(st.allowed)}</span>
               <span class="k">Allowed</span></div>
          <div class="sys-item"><span class="v ${st.denied ? 'warn' : ''}">${fmt(st.denied)}</span>
               <span class="k">Denied</span></div>
          <div class="sys-item opt"><span class="v ${th.matched ? 'warn' : 'ok'}">${fmt(th.matched)}</span>
               <span class="k">Signature hits</span></div>
          <div class="sys-item"><span class="v ${gap ? (ag.open ? 'warn' : 'bad') : 'ok'}">${esc(ag.label)}</span>
               <span class="k">Boundary</span></div>
          <div class="sys-item"><span class="v ${mw.enabled ? (mw.detections ? 'bad' : 'ok') : 'warn'}">${
               mw.enabled ? fmt(mw.detections) : 'Off'}</span>
               <span class="k">Malware</span></div>`;

        /* A count beside the nav entry, so a detection is visible from
         * whatever page the operator happens to be on. */
        const tag = document.querySelector('[data-tag="malware"]');
        if (tag) {
            tag.textContent = mw.detections ? String(mw.detections) : '';
            tag.className = 'nav-tag' + (mw.detections ? ' bad' : '');
        }
        const gtag = document.querySelector('[data-tag="airgap"]');
        if (gtag) {
            gtag.textContent = gap ? (ag.open ? 'ON' : 'SHUT') : '';
            gtag.className = 'nav-tag' + (gap ? (ag.open ? ' warn' : ' bad') : '');
        }
    } catch (e) { /* the page itself will report a real failure */ }
}


/* ── audit ─────────────────────────────────────────────────────
 *
 * Deliberately plain. This page is read when something has gone wrong and
 * somebody is trying to establish a sequence of events, so it is a table
 * in time order with nothing collapsed, nothing paginated away, and the
 * source address beside every row.
 */
const AUDIT_LABEL = {
    'auth.login':        'Sign-in',
    'auth.logout':       'Sign-out',
    'authz.deny':        'Refused: not an administrator',
    'csrf.reject':       'Refused: bad CSRF token',
    'airgap.mode':       'Air gap mode',
    'malware.mode':      'Malware scanner',
    'malware.reload':    'Signature reload',
    'interface.admin':   'Interface link state',
    'account.password':  'Password change',
    'config.apply':      'Configuration applied',
    'config.rollback':   'Configuration rolled back',
    'config.write':      'Configuration change',
    'audit.verify':      'Trail verified',
    'daemon.start':      'Appliance started',
    'daemon.stop':       'Appliance stopped'
};

async function renderAudit() {
    const d = await api('/api/audit');
    const ev = d.events || [];

    const rows = ev.map(e => `<tr class="${e.result === 'ok' ? '' : 'cur'}">
        <td class="mono small">${new Date(e.when * 1000).toLocaleString()}</td>
        <td class="mono">${fmt(e.seq)}</td>
        <td><b>${esc(e.actor)}</b></td>
        <td class="mono small">${esc(e.from)}</td>
        <td>${esc(AUDIT_LABEL[e.action] || e.action)}
            <div class="sub mono">${esc(e.target)}</div></td>
        <td>${e.result === 'ok'     ? '<span class="pill ok">Done</span>'
           : e.result === 'denied'  ? '<span class="pill bad">Refused</span>'
                                    : '<span class="pill warn">Failed</span>'}</td>
        <td class="sub">${esc(e.detail)}</td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
      ${roleBadge()}
      <div class="kpi-row">
        <div class="kpi"><div class="kpi-n">${fmt(d.records)}</div>
          <div class="kpi-l">Records</div>
          <div class="kpi-sub">since this trail was started</div></div>
        <div class="kpi ${d.persistent ? 'ok' : 'danger'}">
          <div class="kpi-n">${d.persistent ? 'ON DISK' : 'MEMORY'}</div>
          <div class="kpi-l">Storage</div>
          <div class="kpi-sub mono small">${esc(d.path)}</div></div>
        <div class="kpi ${d.write_errors ? 'danger' : ''}">
          <div class="kpi-n">${fmt(d.write_errors)}</div>
          <div class="kpi-l">Write failures</div>
          <div class="kpi-sub">records that reached memory only</div></div>
        <div class="kpi info"><div class="kpi-n">${ev.length}</div>
          <div class="kpi-l">Shown here</div>
          <div class="kpi-sub">the full trail is the file above</div></div>
      </div>

      ${!d.persistent ? `<div class="note bad">The trail is not reaching disk.
        Records are kept in memory and will be lost on restart &mdash; which is
        the one time the trail is most likely to be wanted.</div>` : ''}

      <div class="panel">
        <h3>Chain
          <span class="right">${isAdmin()
            ? '<button class="mini" id="au-verify">Verify now</button>' : ''}</span></h3>
        <p style="font-size:13px" id="au-result">Each record carries a SHA-256
        over the record before it. Removing a line, reordering two, or editing a
        field breaks every hash after it, and verification names the first record
        that no longer follows.</p>
        <div class="note">This does not make the trail unalterable &mdash; nothing
        on a box an attacker owns can be. It turns a silent deletion into a
        visible gap, which is the property that is actually useful afterwards.</div>
      </div>

      <div class="panel">
        <h3>Administrative actions<span class="right">newest first</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>When</th><th>#</th><th>Who</th><th>From</th>
            <th>Action</th><th>Result</th><th>Detail</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="7" class="empty">
            Nothing recorded yet.</td></tr>`}</tbody>
        </table></div>
      </div>`;

    const vb = document.getElementById('au-verify');
    if (vb) vb.addEventListener('click', async () => {
        vb.disabled = true;
        try {
            const r = await api('/api/audit/verify', { method: 'POST' });
            const el = document.getElementById('au-result');
            el.innerHTML = r.intact
                ? `<span class="pill ok">Chain intact</span> ${esc(r.detail)}`
                : `<span class="pill bad">Broken</span> ${esc(r.detail)}`;
            toast(r.intact ? 'Audit chain verified' : 'Audit chain is broken', !r.intact);
        } catch (e) { toast(e.message, true); }
        vb.disabled = false;
    });
}

const VIEWS = {
    monitor:     renderMonitor,
    events:      renderBlockEvents,
    diagnostics: renderDiagnostics,
    interfaces:  renderInterfaces,
    vlans:       renderVLANs,
    wan:         renderWAN,
    vpn:         renderVPN,
    malware:     renderMalware,
    airgap:      renderAirgap,
    threat:      renderThreat,
    policy:      renderPolicy,
    portal:      renderPortal,
    revisions:   renderRevisions,
    audit:       renderAudit,
    accounts:    renderAccounts
};
let current = 'monitor';
let timer = null;

async function show(view) {
    if (!VIEWS[view]) view = 'monitor';
    current = view;

    document.querySelectorAll('.navbtn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === view));

    const meta = PAGE[view] || { label: 'Console', sub: '' };
    const t = document.getElementById('page-title');
    const u = document.getElementById('page-sub');
    if (t) t.textContent = meta.label;
    if (u) u.textContent = meta.sub || '';

    try {
        await VIEWS[view]();
        if (view === 'vlans') wireMatrix();
        sysbar();
    }
    catch (err) {
        if (err instanceof AuthError) { chrome(false); renderLogin('Session ended. Sign in again.'); return; }
        document.getElementById('content').innerHTML =
            `<div class="panel"><h3>Could not load this page</h3>
             <p class="no">${esc(err.message)}</p></div>`;
    }
}

buildNav();

document.getElementById('side-toggle').addEventListener('click', () =>
    document.getElementById('side').classList.toggle('open'));

document.getElementById('btn-logout').addEventListener('click', async () => {
    try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) { /* already gone */ }
    state.user = state.role = state.csrf = null;
    chrome(false);
    renderLogin('Signed out.');
});

async function boot() {
    try {
        const me = await api('/api/auth/whoami');
        state.user = me.user; state.role = me.role; state.csrf = me.csrf;
        chrome(true);
        show('monitor');
    } catch (e) {
        chrome(false);
        renderLogin(e instanceof AuthError ? '' : e.message);
    }
}

/* Refresh only the data views, and only while signed in -- reloading under a
 * prompt or a half-filled form would throw the change away. */
function startRefresh() {
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
        if (state.csrf && current !== 'revisions' && current !== 'diagnostics'
                       && current !== 'accounts')
            show(current);
    }, 5000);
}

boot();
startRefresh();

/* ══════════════════════════════════════════════════════════════════════
 *  Interfaces
 *
 *  Reported from the kernel, not from the configuration. The column that
 *  earns its place is "Link": a port that is administratively up with no
 *  carrier is the single most common fault on an appliance, and it is
 *  invisible on a page that only plays the configuration back.
 * ══════════════════════════════════════════════════════════════════════ */

const KIND_LABEL = {
    physical: 'Port', loopback: 'Loopback', bridge: 'Bridge',
    vlan: 'VLAN', tunnel: 'Tunnel', virtual: 'Virtual'
};

function linkState(f) {
    if (!f.admin_up)            return ['bad',  'Down',      'administratively down'];
    if (!f.carrier && f.kind === 'physical')
                                return ['warn', 'No carrier','up, but nothing is plugged in'];
    if (f.oper === 'up')        return ['ok',   'Up',        ''];
    if (f.oper === 'dormant')   return ['warn', 'Dormant',   ''];
    return ['mut', f.oper ? f.oper.charAt(0).toUpperCase() + f.oper.slice(1) : 'Unknown', ''];
}

function speedText(f) {
    if (f.speed > 0) {
        const s = f.speed >= 1000 ? (f.speed / 1000) + ' Gb/s' : f.speed + ' Mb/s';
        return f.duplex ? `${s} ${esc(f.duplex)}` : s;
    }
    return '<span class="muted">&mdash;</span>';
}

async function renderInterfaces() {
    const d = await api('/api/interfaces');
    const list = d.interfaces || [];

    const phys   = list.filter(f => f.kind === 'physical');
    const up     = phys.filter(f => f.admin_up && f.carrier).length;
    const nocarr = phys.filter(f => f.admin_up && !f.carrier).length;
    const errs   = list.reduce((a, f) => a + f.rx_errors + f.tx_errors, 0);
    const drops  = list.reduce((a, f) => a + f.rx_dropped + f.tx_dropped, 0);

    const rows = list.map(f => {
        const [cls, label, why] = linkState(f);
        return `<tr>
            <td>
              <span class="dot ${cls === 'mut' ? '' : cls}"></span>
              <b class="mono">${esc(f.name)}</b>
              ${f.wan ? '<span class="pill info" style="margin-left:6px">WAN</span>' : ''}
            </td>
            <td><span class="pill mut">${esc(KIND_LABEL[f.kind] || f.kind)}</span></td>
            <td><span class="pill ${cls}">${esc(label)}</span>
                ${why ? `<div class="sub">${esc(why)}</div>` : ''}</td>
            <td>${speedText(f)}</td>
            <td class="mono">${f.ipv4 ? esc(f.ipv4) : '<span class="muted">unaddressed</span>'}</td>
            <td class="mono small">${esc(f.mac || '')}</td>
            <td class="num mono">${f.mtu || ''}</td>
            <td>${f.zone ? zoneChip(f.zone) : '<span class="muted">&mdash;</span>'}</td>
            <td class="num mono">${bytes(f.rx_bytes)}</td>
            <td class="num mono">${bytes(f.tx_bytes)}</td>
            <td class="num mono ${(f.rx_errors + f.tx_errors) ? 'no' : 'muted'}">${fmt(f.rx_errors + f.tx_errors)}</td>
            <td class="num mono ${(f.rx_dropped + f.tx_dropped) ? 'warn' : 'muted'}">${fmt(f.rx_dropped + f.tx_dropped)}</td>
            <td>${isAdmin() && f.kind === 'physical'
                   ? `<button class="mini ${f.admin_up ? '' : 'on'}" data-if="${esc(f.name)}"
                        data-up="${f.admin_up ? 'false' : 'true'}">${f.admin_up ? 'Shut down' : 'Bring up'}</button>`
                   : ''}</td>
        </tr>`;
    }).join('');

    document.getElementById('content').innerHTML = `
      ${roleBadge()}
      <div class="kpi-row">
        <div class="kpi ok"><div class="kpi-n">${up}</div><div class="kpi-l">Ports up</div>
             <div class="kpi-sub">${phys.length} physical total</div></div>
        <div class="kpi ${nocarr ? 'warn' : ''}"><div class="kpi-n">${nocarr}</div>
             <div class="kpi-l">No carrier</div>
             <div class="kpi-sub">${nocarr ? 'up with nothing attached' : 'every live port has a link'}</div></div>
        <div class="kpi ${errs ? 'danger' : ''}"><div class="kpi-n">${fmt(errs)}</div>
             <div class="kpi-l">Errors</div><div class="kpi-sub">rx + tx, since boot</div></div>
        <div class="kpi ${drops ? 'warn' : ''}"><div class="kpi-n">${fmt(drops)}</div>
             <div class="kpi-l">Dropped</div><div class="kpi-sub">rx + tx, since boot</div></div>
      </div>

      <div class="panel">
        <h3>Interfaces<span class="right">${list.length} reported by the kernel</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr>
            <th>Interface</th><th>Type</th><th>Link</th><th>Speed</th><th>Address</th>
            <th>MAC</th><th class="num">MTU</th><th>Zone</th>
            <th class="num">RX</th><th class="num">TX</th>
            <th class="num">Errors</th><th class="num">Dropped</th><th></th>
          </tr></thead>
          <tbody>${rows || '<tr><td colspan="13" class="empty">No interfaces reported.</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="note info">Counters are read from the kernel and reset only on
      reboot. A port shown as <b>No carrier</b> is configured and enabled but has
      nothing connected &mdash; that is a cable, not a configuration fault.</div>`;

    document.querySelectorAll('[data-if]').forEach(b =>
        b.addEventListener('click', async () => {
            const name = b.dataset.if, up = b.dataset.up === 'true';
            if (!up && !confirm(`Shut down ${name}? Anything reached through it will drop.`)) return;
            b.disabled = true;
            try {
                await api(`/api/interfaces/${encodeURIComponent(name)}/admin`,
                          { method: 'POST', body: { up } });
                toast(`${name} is now ${up ? 'up' : 'down'}`);
                show('interfaces');
            } catch (e) { toast(e.message, true); b.disabled = false; }
        }));
}

/* ══════════════════════════════════════════════════════════════════════
 *  Live malware protection
 * ══════════════════════════════════════════════════════════════════════ */

function ago(ts) {
    if (!ts) return 'never';
    const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (s < 60)    return s + 's ago';
    if (s < 3600)  return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
}

async function renderMalware() {
    const d = await api('/api/malware');

    const events = (d.events || []).map(e => `<tr>
        <td class="mono small">${new Date(e.when * 1000).toLocaleString()}</td>
        <td><span class="sev s${e.severity}">${e.severity}</span></td>
        <td><b>${esc(e.name)}</b>
            ${e.ctype ? `<div class="sub mono">${esc(e.ctype)}</div>` : ''}</td>
        <td><span class="pill mut">${esc(e.source)}</span></td>
        <td class="mono small">${esc(e.src)}<span class="muted"> &rarr; </span>${esc(e.dst)}</td>
        <td class="num mono">${bytes(e.size)}</td>
        <td>${e.blocked ? '<span class="pill bad">Blocked</span>'
                        : '<span class="pill warn">Alerted</span>'}</td>
        <td class="mono small muted">${esc((e.sha256 || '').slice(0, 16))}${e.sha256 ? '&hellip;' : ''}</td>
      </tr>`).join('');

    const pct = d.bytes + d.opaque > 0
        ? Math.round(d.bytes * 100 / (d.bytes + d.opaque)) : 0;

    /*
     * Coverage, which is NOT the same thing as "enabled".
     *
     * Scanning runs per segment. The engine can be on, blocking, with a
     * loaded database, over a network where no segment has it switched on
     * -- and the old header said "ON" for that appliance. So the state
     * shown here is the AND of the two: an engine that is on but covers
     * nothing reads "NO COVERAGE", in the same red as off, because that is
     * what it is.
     */
    const cov    = d.coverage || { segments: 0, segments_scanned: 0, uncovered: [] };
    const gaps   = cov.uncovered || [];
    const covered = cov.segments_scanned || 0;
    const live   = d.enabled && covered > 0;

    const headState = !d.enabled ? 'OFF'
                    : covered === 0 ? 'NO COVERAGE'
                    : d.block ? 'ON' : 'DETECT';
    const headClass = !d.enabled ? 'danger'
                    : covered === 0 ? 'danger'
                    : d.block ? 'ok' : 'warn';
    const headSub   = !d.enabled ? 'nothing is being scanned'
                    : covered === 0
                      ? 'the engine is running but no segment is scanned'
                      : (d.block ? 'detections are dropped'
                                 : 'detections are reported only');

    const gapRows = gaps.map(g => `<tr>
        <td><b>${esc(g.name)}</b></td>
        <td class="mono">VLAN ${g.vlan}</td>
        <td><span class="pill bad">Not scanned</span></td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
      ${roleBadge()}
      ${d.enabled && covered === 0 ? `<div class="note bad">
        <b>Malware protection is enabled but covers nothing.</b>
        Scanning is set per segment, and no segment has it switched on, so
        no transfer on this appliance is being inspected. Turn on
        <span class="mono">malware_scan</span> for the segments that carry
        downloads.</div>` : ''}
      <div class="kpi-row">
        <div class="kpi ${headClass}">
          <div class="kpi-n">${headState}</div>
          <div class="kpi-l">Protection</div>
          <div class="kpi-sub">${headSub}</div></div>
        <div class="kpi ${gaps.length ? 'warn' : (covered ? 'ok' : 'danger')}">
          <div class="kpi-n">${covered}&thinsp;/&thinsp;${cov.segments || 0}</div>
          <div class="kpi-l">Segments covered</div>
          <div class="kpi-sub">${gaps.length
            ? `${gaps.length} segment(s) unscanned`
            : (cov.segments ? 'every segment is scanned' : 'no segments configured')}</div></div>
        <div class="kpi ${d.detections ? 'danger' : ''}">
          <div class="kpi-n">${fmt(d.detections)}</div><div class="kpi-l">Detections</div>
          <div class="kpi-sub">${fmt(d.blocked)} blocked</div></div>
        <div class="kpi"><div class="kpi-n">${fmt(d.objects)}</div>
          <div class="kpi-l">Objects scanned</div>
          <div class="kpi-sub">${bytes(d.bytes)} inspected</div></div>
        <div class="kpi info"><div class="kpi-n">${d.flows_active}</div>
          <div class="kpi-l">Flows in scan</div>
          <div class="kpi-sub">${fmt(d.flows_dropped)} not tracked</div></div>
        <div class="kpi"><div class="kpi-n">${fmt(d.hashes)}</div>
          <div class="kpi-l">Signatures</div>
          <div class="kpi-sub">${fmt(d.patterns)} byte pattern(s)</div></div>
      </div>

      ${isAdmin() ? `<div class="panel"><h3>Control</h3>
        <div class="btn-row">
          <button class="mini ${d.enabled ? 'on' : ''}" id="mw-en"
            data-v="${d.enabled ? 'false' : 'true'}">${d.enabled ? 'Scanning enabled' : 'Enable scanning'}</button>
          <button class="mini ${d.block ? 'bad' : 'warn'}" id="mw-bl"
            data-v="${d.block ? 'false' : 'true'}">${d.block ? 'Blocking' : 'Detect only'}</button>
          <button class="mini" id="mw-rl">Reload signatures</button>
        </div>
        <div class="note">Database <b>${esc(d.db_version)}</b>${d.db_loaded
          ? `, loaded ${esc(ago(d.db_loaded))}` : ', never loaded'}.
          Objects are scanned up to ${bytes(d.max_object)};
          ${fmt(d.truncated)} were larger and were inspected only that far.</div>
      </div>` : ''}

      <div class="panel">
        <h3>Detections<span class="right">most recent first</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>When</th><th>Sev</th><th>Detection</th><th>Matched by</th>
            <th>Source &rarr; destination</th><th class="num">Size</th>
            <th>Action</th><th>SHA-256</th></tr></thead>
          <tbody>${events || '<tr><td colspan="8" class="empty">Nothing detected.</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="panel">
        <h3>Coverage<span class="right">what was actually inspected</span></h3>
        <table class="dt">
          <tbody>
            <tr><td>Objects fully inspected
                    <div class="sub">hashed whole and compared against the database</div></td>
                <td class="num mono">${fmt(d.objects)}</td>
                <td class="num mono">${bytes(d.bytes)}</td></tr>
            <tr><td>Objects too large, <b>not</b> hash-inspected
                    <div class="sub">a hash of part of a file cannot match a database of whole
                        files, so no hash verdict is claimed here; byte patterns still ran</div></td>
                <td class="num mono ${d.partial ? 'warn' : 'muted'}">${fmt(d.partial)}</td>
                <td class="num mono muted">&mdash;</td></tr>
            <tr><td>Encrypted, not inspected
                    <div class="sub">TLS and other opaque sessions are counted, not guessed at</div></td>
                <td class="num mono muted">&mdash;</td>
                <td class="num mono">${bytes(d.opaque)}</td></tr>
          </tbody>
        </table>
        <div class="note warn">This scans plaintext transfers. Encrypted downloads
        pass through unread unless the session is terminated on the appliance, so
        this is one layer among several and not an endpoint anti-virus.</div>
      </div>

      <div class="panel ${gaps.length ? 'danger-panel' : ''}">
        <h3>Segments not scanned
          <span class="right">${covered} of ${cov.segments || 0} covered</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>Segment</th><th>VLAN</th><th>State</th></tr></thead>
          <tbody>${gapRows || `<tr><td colspan="3" class="empty">
            Every configured segment is scanned.</td></tr>`}</tbody>
        </table></div>
        <div class="note">Traffic that matches no configured segment is not
        scanned either &mdash; the flag is read from the segment, so there is
        nowhere to read it from. Set <span class="mono">malware_scan = yes</span>
        under the segment in the appliance configuration.</div>
      </div>`;

    if (!isAdmin()) return;
    const post = async (path, body) => {
        try { await api(path, { method: 'POST', body }); show('malware'); }
        catch (e) { toast(e.message, true); }
    };
    document.getElementById('mw-en').addEventListener('click', e =>
        post('/api/malware/mode', { enabled: e.target.dataset.v === 'true' }));
    document.getElementById('mw-bl').addEventListener('click', e =>
        post('/api/malware/mode', { block: e.target.dataset.v === 'true' }));
    document.getElementById('mw-rl').addEventListener('click', async () => {
        try { const r = await api('/api/malware/reload', { method: 'POST' });
              toast(`${r.hashes} signature(s) loaded`); show('malware'); }
        catch (e) { toast(e.message, true); }
    });
}

/* ══════════════════════════════════════════════════════════════════════
 *  Air gap
 * ══════════════════════════════════════════════════════════════════════ */

const AG_MODES = [
    ['connected',     'Connected',       'Normal operation. Nothing is enforced here.'],
    ['scheduled',     'Scheduled gap',   'Shut except inside the windows below.'],
    ['inbound-only',  'Diode: inbound',  'Traffic may arrive. Nothing may leave.'],
    ['outbound-only', 'Diode: outbound', 'Traffic may leave. No session may be opened from outside.'],
    ['isolated',      'Isolated',        'Nothing crosses the boundary in either direction.'],
    ['manual',        'Manual transfer', 'Isolated, and the appliance fetches nothing of its own.']
];

async function renderAirgap() {
    const d = await api('/api/airgap');
    const closed = !d.open;

    const windows = (d.windows || []).map(w => `<tr>
        <td><b>${esc(w.name)}</b></td>
        <td>${esc(w.days)}</td>
        <td class="mono">${esc(w.start)} &ndash; ${esc(w.end)}</td>
        <td>${w.in  ? '<span class="pill ok">Inbound</span>'  : '<span class="pill mut">No inbound</span>'}</td>
        <td>${w.out ? '<span class="pill ok">Outbound</span>' : '<span class="pill mut">No outbound</span>'}</td>
      </tr>`).join('');

    const events = (d.events || []).map(e => `<tr>
        <td class="mono small">${new Date(e.when * 1000).toLocaleString()}</td>
        <td>${e.opened ? '<span class="pill ok">Opened</span>'
                       : '<span class="pill bad">Closed</span>'}</td>
        <td><span class="pill mut">${esc(e.mode)}</span></td>
        <td>${esc(e.reason)}</td>
      </tr>`).join('');

    /* What each subsystem would reach out for, named in the operator's
     * terms rather than the module's. A row reading zero while the gap is
     * shut is the signal that something is not being gated -- the reason
     * this table shows every subsystem rather than only the busy ones. */
    const EGRESS_WHAT = {
        feeds:     'Reputation and blocklist refreshes',
        telemetry: 'Syslog and NetFlow to your collectors',
        ha:        'Configuration push to the standby node',
        gwmon:     'Gateway reachability probes'
    };
    const egress = (d.egress || []).map(e => `<tr>
        <td><b>${esc(e.subsystem)}</b></td>
        <td class="sub">${esc(EGRESS_WHAT[e.subsystem] || '')}</td>
        <td style="text-align:right" class="mono">${
            e.refused ? `<span class="pill bad">${fmt(e.refused)}</span>`
                      : '<span class="pill mut">0</span>'}</td>
      </tr>`).join('') ||
      `<tr><td colspan="3" class="empty">No subsystems reported.</td></tr>`;

    const modeCards = AG_MODES.map(([id, label, desc]) => `
      <tr class="${d.mode === id ? 'cur' : ''}">
        <td><b>${esc(label)}</b>
            ${d.mode === id ? '<span class="active-pill" style="margin-left:6px">Active</span>' : ''}
            <div class="sub">${esc(desc)}</div></td>
        <td style="text-align:right">
          ${isAdmin() && d.mode !== id
            ? `<button class="mini ${id === 'connected' ? '' : 'warn'}" data-mode="${id}">Select</button>`
            : ''}
        </td>
      </tr>`).join('');

    document.getElementById('content').innerHTML = `
      ${roleBadge()}
      <div class="kpi-row">
        <div class="kpi ${closed ? 'danger' : 'ok'}">
          <div class="kpi-n">${closed ? 'SHUT' : 'OPEN'}</div>
          <div class="kpi-l">Boundary</div>
          <div class="kpi-sub">${esc(d.label)}</div></div>
        <div class="kpi"><div class="kpi-n">${fmt(d.denied_out)}</div>
          <div class="kpi-l">Denied outbound</div>
          <div class="kpi-sub">${fmt(d.passed_out)} allowed</div></div>
        <div class="kpi"><div class="kpi-n">${fmt(d.denied_in)}</div>
          <div class="kpi-l">Denied inbound</div>
          <div class="kpi-sub">${fmt(d.passed_in)} allowed</div></div>
        <div class="kpi ${d.blocked_fetches ? 'info' : ''}">
          <div class="kpi-n">${fmt(d.blocked_fetches)}</div>
          <div class="kpi-l">Own fetches refused</div>
          <div class="kpi-sub">updates and feeds held back</div></div>
        <div class="kpi"><div class="kpi-n">${d.next_change
            ? new Date(d.next_change * 1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})
            : '&mdash;'}</div>
          <div class="kpi-l">Next change</div>
          <div class="kpi-sub">${d.next_change
            ? new Date(d.next_change * 1000).toLocaleDateString() : 'nothing scheduled'}</div></div>
      </div>

      <div class="panel ${closed ? 'danger-panel' : ''}">
        <h3>Current state<span class="right">changed ${esc(ago(d.last_change))}</span></h3>
        <p style="font-size:13px">${esc(d.reason)}</p>
        ${d.require_time_sync && !d.time_synced ? `<div class="note warn">
          The clock is not synchronised. A scheduled gap is decided entirely by
          the local clock, so it stays shut until the time can be trusted.</div>` : ''}
      </div>

      <div class="panel">
        <h3>Mode</h3>
        <div class="tw"><table class="dt"><tbody>${modeCards}</tbody></table></div>
      </div>

      <div class="panel">
        <h3>Transfer windows<span class="right">${(d.windows || []).length} defined</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>Name</th><th>Days</th><th>Time</th>
            <th>Inbound</th><th>Outbound</th></tr></thead>
          <tbody>${windows || `<tr><td colspan="5" class="empty">
            No windows. In scheduled mode the gap never opens &mdash; which is the
            safe direction, but probably not what was intended.</td></tr>`}</tbody>
        </table></div>
        <div class="note">Windows are set in <span class="mono">[airgap]</span> in the
        appliance configuration, as
        <span class="mono">window = name,days,HH:MM,HH:MM,in,out</span>.</div>
      </div>

      <div class="panel">
        <h3>The appliance's own traffic
          <span class="right">${closed ? 'held back' : 'permitted'}</span></h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>Subsystem</th><th>What it reaches out for</th>
            <th style="text-align:right">Refused</th></tr></thead>
          <tbody>${egress}</tbody>
        </table></div>
        <div class="note">This column is what separates an air gap from a strict
        firewall. An appliance that drops every user packet and still fetches its
        own blocklist is reachable &mdash; by one sanctioned path, which is the
        most valuable one on the network.</div>
      </div>

      <div class="panel">
        <h3>State changes</h3>
        <div class="tw"><table class="dt">
          <thead><tr><th>When</th><th>Transition</th><th>Mode</th><th>Reason</th></tr></thead>
          <tbody>${events || '<tr><td colspan="4" class="empty">No changes recorded.</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="note info">Enforcement is in the datapath for traffic crossing
      the appliance, and at each subsystem for traffic the appliance originates.
      A physical air gap is a property of the cable; this is the enforced, logged
      and scheduled equivalent, which cannot be forgotten about and records every
      crossing it refused.</div>`;

    document.querySelectorAll('[data-mode]').forEach(b =>
        b.addEventListener('click', async () => {
            const mode = b.dataset.mode;
            const label = (AG_MODES.find(m => m[0] === mode) || [, mode])[1];
            if (mode !== 'connected' &&
                !confirm(`Switch the boundary to "${label}"?\n\nTraffic crossing the WAN boundary will be refused according to that mode, immediately.`))
                return;
            b.disabled = true;
            try { await api('/api/airgap/mode', { method: 'POST', body: { mode } });
                  toast(`Air gap: ${label}`); show('airgap'); }
            catch (e) { toast(e.message, true); b.disabled = false; }
        }));
}
