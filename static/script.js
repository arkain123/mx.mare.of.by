/* ---------- Theme ---------- */
function applyTheme(pref) {
    var resolved = pref === 'auto'
        ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
        : pref;
    document.documentElement.setAttribute('data-theme', resolved);
}

function cycleTheme() {
    var current = 'auto';
    try { current = localStorage.getItem('mx_tools_theme') || 'auto'; } catch (e) {}
    var next = current === 'auto' ? 'dark' : current === 'dark' ? 'light' : 'auto';
    try { localStorage.setItem('mx_tools_theme', next); } catch (e) {}
    applyTheme(next);
}

/* ---------- Tabs ---------- */
document.querySelectorAll('nav .tab').forEach(function (a) {
    a.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelectorAll('nav .tab').forEach(function (t) { t.classList.remove('active'); });
        document.querySelectorAll('.tab-content').forEach(function (s) { s.classList.remove('active'); });
        a.classList.add('active');
        var target = document.getElementById('tab-' + a.dataset.tab);
        if (target) target.classList.add('active');
    });
});

/* ---------- Helpers ---------- */
function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function field(label, value) {
    return '<tr><td>' + esc(label) + '</td><td>' + value + '</td></tr>';
}

function statusDiv(kind, text) {
    return '<div class="status ' + kind + '">' + esc(text) + '</div>';
}

function boolTag(v, yes, no) {
    return v
        ? '<span class="tag-ok">' + esc(yes || 'yes') + '</span>'
        : '<span class="tag-bad">' + esc(no || 'no') + '</span>';
}

/* ---------- Individual renderers ---------- */
function renderSPF(data) {
    if (data.error) return statusDiv('red', data.error);
    var rows = '';
    rows += field('Valid', boolTag(data.valid));
    if (data.record) rows += field('Record', '<code>' + esc(data.record) + '</code>');
    if (data.version) rows += field('Version', esc(data.version));
    if (data.redirect) rows += field('Redirect', '<code>' + esc(data.redirect) + '</code>');
    if (data.dns_lookups != null) {
        var warn = data.dns_lookups > 10;
        rows += field('DNS lookups', (warn ? '<span class="tag-bad">' : '<span class="tag-ok">')
            + data.dns_lookups + '</span> / 10');
    }
    if (data.warnings && data.warnings.length) {
        rows += field('Warnings',
            '<ul class="err-list">' +
            data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('') +
            '</ul>');
    }
    return '<table>' + rows + '</table>';
}

function renderDMARC(data) {
    if (data.error) return statusDiv('red', data.error);
    var rows = '';
    rows += field('Valid', boolTag(data.valid));
    if (data.record) rows += field('Record', '<code>' + esc(data.record) + '</code>');
    if (data.location) rows += field('Location', '<code>' + esc(data.location) + '</code>');
    if (data.policy) rows += field('Policy (p)', '<code>' + esc(data.policy) + '</code>');
    if (data.tags) {
        var tagList = Object.keys(data.tags).map(function (k) {
            return '<code>' + esc(k) + '=' + esc(data.tags[k]) + '</code>';
        }).join('<br>');
        rows += field('Tags', tagList);
    }
    if (data.warnings && data.warnings.length) {
        rows += field('Warnings',
            '<ul class="err-list">' +
            data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('') +
            '</ul>');
    }
    return '<table>' + rows + '</table>';
}

function renderDKIM(data) {
    if (data.error) return statusDiv('red', data.error);

    if (data.selector) {
        var d = data.details || {};
        var html = statusDiv(data.valid ? 'green' : 'red', data.valid ? 'Valid' : 'Not found / invalid');
        var rows = '';
        rows += field('Selector', esc(data.selector));
        if (d.name) rows += field('FQDN', '<code>' + esc(d.name) + '</code>');
        if (d.tags) {
            Object.keys(d.tags).forEach(function (k) {
                var v = d.tags[k];
                if (k === 'p' && v.length > 80) v = v.slice(0, 80) + '…';
                rows += field(k, '<code>' + esc(v) + '</code>');
            });
        }
        if (d.error) rows += field('Error', esc(d.error));
        return html + '<table>' + rows + '</table>';
    }

    if (data.valid && data.selectors) {
        var html = statusDiv('green', 'Found on: ' + data.selectors.join(', '));
        for (var i = 0; i < data.details.length; i++) {
            var dd = data.details[i];
            html += '<h3>' + esc(dd.name) + '</h3>';
            var rows2 = '';
            if (dd.tags) {
                Object.keys(dd.tags).forEach(function (k) {
                    var v = dd.tags[k];
                    if (k === 'p' && v.length > 80) v = v.slice(0, 80) + '…';
                    rows2 += field(k, '<code>' + esc(v) + '</code>');
                });
            }
            html += '<table>' + rows2 + '</table>';
        }
        return html;
    }

    return statusDiv('orange',
        'No DKIM on common selectors. Tried: ' + (data.tried || []).join(', '));
}

function renderMX(data) {
    if (!data.valid) return statusDiv('red', data.error || 'no MX records');
    var html = statusDiv('green', data.records.length + ' MX record(s)');
    html += '<table><thead><tr><th>Priority</th><th>Host</th><th>Port 25</th></tr></thead><tbody>';
    data.records.forEach(function (r) {
        var p = r.port25 || {};
        var pStatus = p.reachable
            ? '<span class="tag-ok">reachable</span>'
            : '<span class="tag-bad">' + esc(p.error || 'unreachable') + '</span>';
        html += '<tr><td>' + r.priority + '</td><td><code>' + esc(r.host) + '</code></td><td>' + pStatus + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function renderBlacklist(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var html = '<p><b>IP:</b> <code>' + esc(data.ip) + '</code></p>';
    html += data.listed_count > 0
        ? statusDiv('red', 'Listed on ' + data.listed_count + ' blacklist(s)')
        : statusDiv('green', 'Not listed anywhere');
    html += '<table><thead><tr><th>Blacklist</th><th>Status</th></tr></thead><tbody>';
    data.results.forEach(function (r) {
        var s;
        if (r.listed === true) s = '<span class="tag-bad">LISTED</span>';
        else if (r.listed === false) s = '<span class="tag-ok">clean</span>';
        else s = '<span class="tag-warn">' + esc(r.status) + '</span>';
        html += '<tr><td>' + esc(r.label) + '<br><small class="muted">' + esc(r.zone) + '</small></td><td>' + s + '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
}

function renderSMTP(data) {
    if (data.error) return statusDiv('red', data.error);

    if (!data.valid) {
        var info = statusDiv('orange', 'no SMTP port reachable from this host');
        info += '<p class="muted">Probed ports 25, 587, 2525 and 465 on every MX IP. '
              + 'Outbound port 25 is blocked by many VPS providers, so this alone '
              + 'does not indicate a problem with the domain.</p>';
        // still render the per-host attempts below so the user sees errors
        info += renderSmtpAttempts(data);
        return info;
    }

    var head = statusDiv('green', 'at least one SMTP port reachable');
    head += '<p><b>MX source:</b> <code>' + esc(data.mx_source) + '</code></p>';
    return head + renderSmtpAttempts(data);
}

function renderSmtpAttempts(data) {
    var html = '';
    (data.hosts || []).forEach(function (h) {
        html += '<h3>' + esc(h.host)
              + ' <span class="muted">(priority ' + h.priority + ')</span></h3>';

        var ips = (h.ipv4 || []).concat(h.ipv6 || []);
        if (!ips.length) {
            html += '<p class="muted">no A/AAAA records</p>';
            return;
        }

        var byIp = {};
        h.attempts.forEach(function (a) {
            (byIp[a.ip] = byIp[a.ip] || []).push(a);
        });

        Object.keys(byIp).forEach(function (ip) {
            html += '<p><b>' + esc(ip) + '</b></p>';
            html += '<table><thead><tr>'
                  + '<th>Port</th><th>TLS</th><th>Status</th><th>Detail</th>'
                  + '</tr></thead><tbody>';
            byIp[ip].forEach(function (a) {
                var cls;
                if (a.status === 'ok') cls = 'tag-ok';
                else if (a.status === 'connect_error' || a.status === 'error'
                      || a.status === 'smtp_error' || a.status === 'disconnected') cls = 'muted';
                else cls = 'tag-warn';

                var detail = '';
                if (a.error) detail = a.error;
                else if (a.status === 'ok') {
                    var parts = [];
                    if (a.banner) parts.push(a.banner);
                    if (a.tls_used) parts.push('TLS active');
                    if (a.features && a.features.length) parts.push(a.features.join(', '));
                    detail = parts.join(' | ');
                } else if (a.tls_error) detail = a.tls_error;
                else if (a.banner) detail = a.banner;

                html += '<tr>'
                      + '<td>' + a.port + '</td>'
                      + '<td>' + esc(a.tls) + '</td>'
                      + '<td><span class="' + cls + '">' + esc(a.status) + '</span></td>'
                      + '<td><code>' + esc(detail) + '</code></td>'
                      + '</tr>';
            });
            html += '</tbody></table>';
        });
    });
    return html;
}

function renderMailbox(data) {
    if (data.error) return statusDiv('red', data.error);
    var verdicts = {
        exists: ['green', 'EXISTS'],
        not_exists: ['red', 'NOT EXISTS'],
        rejected: ['orange', 'REJECTED'],
        rejected_policy: ['orange', 'POLICY BLOCKED'],
        unreachable: ['orange', 'UNREACHABLE'],
        inconclusive: ['orange', 'INCONCLUSIVE']
    };
    var v = verdicts[data.verdict] || ['orange', data.verdict];
    var html = statusDiv(v[0], v[1]);
    html += '<p><b>Email:</b> ' + esc(data.email) + '</p>';
    if (data.server) {
        html += '<p><b>Server:</b> <code>' + esc(data.server) + '</code>'
            + ' <span class="muted">(custom)</span></p>';
    }
    html += '<p><b>MX source:</b> <code>' + esc(data.mx_source) + '</code></p>';

    html += '<h3>MX chain</h3>';
    html += '<table><thead><tr><th>Priority</th><th>Host</th><th>IPv4</th><th>IPv6</th></tr></thead><tbody>';
    data.mx_chain.forEach(function (e) {
        html += '<tr>'
            + '<td>' + e.priority + '</td>'
            + '<td><code>' + esc(e.host) + '</code></td>'
            + '<td><code>' + esc((e.ipv4 || []).join(', ') || '—') + '</code></td>'
            + '<td><code>' + esc((e.ipv6 || []).join(', ') || '—') + '</code></td>'
            + '</tr>';
    });
    html += '</tbody></table>';

    var byIp = {};
    (data.attempts || []).forEach(function (a) {
        (byIp[a.ip] = byIp[a.ip] || []).push(a);
    });

    html += '<h3>Attempts</h3>';
    Object.keys(byIp).forEach(function (ip) {
        html += '<p><b>' + esc(ip) + '</b></p>';
        html += '<table><thead><tr><th>Port</th><th>TLS</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
        byIp[ip].forEach(function (a) {
            var cls;
            if (a.status === 'exists') cls = 'tag-ok';
            else if (a.status === 'not_exists') cls = 'tag-bad';
            else if (a.status === 'connect_error' || a.status === 'error' || a.status === 'smtp_error' || a.status === 'disconnected') cls = 'muted';
            else cls = 'tag-warn';

            var detail = '';
            if (a.rcpt_code) detail = 'rcpt=' + a.rcpt_code + ' ' + (a.rcpt_msg || '');
            else if (a.mail_from_code) detail = 'mail-from=' + a.mail_from_code + ' ' + (a.mail_from_msg || '');
            else if (a.error) detail = a.error;
            else if (a.banner) detail = a.banner;

            html += '<tr>'
                + '<td>' + a.port + '</td>'
                + '<td>' + esc(a.tls) + '</td>'
                + '<td><span class="' + cls + '">' + esc(a.status) + '</span></td>'
                + '<td><code>' + esc(detail) + '</code></td>'
                + '</tr>';
        });
        html += '</tbody></table>';
    });
    return html;
}

function renderPTR(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var html = data.mismatch_count > 0
        ? statusDiv('orange', data.mismatch_count + ' PTR mismatch(es) — check your reverse DNS')
        : statusDiv('green', 'All PTR records match MX hostnames');
    html += '<table><thead><tr><th>MX</th><th>IP</th><th>PTR</th></tr></thead><tbody>';
    (data.records || []).forEach(function (r) {
        (r.ipv4 || []).forEach(function (ip) {
            var ptrs = (r.ptr && r.ptr[ip]) || [];
            var ok = ptrs.indexOf(r.host) !== -1;
            var cell;
            if (!ptrs.length) {
                cell = '<span class="tag-bad">none</span>';
            } else if (ok) {
                cell = '<span class="tag-ok">' + ptrs.map(esc).join(', ') + '</span>';
            } else {
                cell = '<span class="tag-warn">' + ptrs.map(esc).join(', ') + '</span>';
            }
            html += '<tr>'
                + '<td><code>' + esc(r.host) + '</code></td>'
                + '<td><code>' + esc(ip) + '</code></td>'
                + '<td>' + cell + '</td>'
                + '</tr>';
        });
    });
    html += '</tbody></table>';
    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list">'
            + data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('')
            + '</ul>';
    }
    return html;
}

function renderTLSCert(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var html = '';
    (data.hosts || []).forEach(function (h) {
        html += '<h3>' + esc(h.host)
              + ' <span class="muted">(priority ' + h.priority + ')</span></h3>';

        if (!h.ips || !h.ips.length) {
            html += '<p class="muted">no A records</p>';
            return;
        }

        h.ips.forEach(function (item) {
            html += '<p><b>' + esc(item.ip) + '</b></p>';
            if (item.error) {
                html += statusDiv('orange', item.error);
                return;
            }
            var c = item.cert || {};
            var rows = '';
            var issuerCN = (c.issuer && (c.issuer.commonName || c.issuer.organizationName)) || '—';
            var subjectCN = (c.subject && (c.subject.commonName || c.subject.organizationName)) || '—';
            rows += field('Issuer', esc(issuerCN));
            rows += field('Subject', esc(subjectCN));

            var days = c.days_left;
            var daysCell = '—';
            if (days != null) {
                var cls = days < 0 ? 'tag-bad' : days < 30 ? 'tag-warn' : 'tag-ok';
                daysCell = '<span class="' + cls + '">' + days + '</span>';
            }
            rows += field('Expires', esc(c.not_after || '—') + ' (' + daysCell + ' days left)');
            rows += field('Hostname match', boolTag(c.hostname_match, 'matches', 'does NOT match'));

            var san = (c.subject_alt_name || []).join('<br>');
            if (san) rows += field('SAN', '<code>' + san + '</code>');

            html += '<table>' + rows + '</table>';
        });
    });
    return html || statusDiv('orange', 'No TLS certificates retrieved');
}

function renderMTASTS(data) {
    if (!data.valid) {
        var err = statusDiv('red', data.error || 'lookup failed');
        if (data.sts_record) err += '<p><b>Record:</b> <code>' + esc(data.sts_record) + '</code></p>';
        if (data.policy_url) err += '<p><b>Policy URL:</b> <code>' + esc(data.policy_url) + '</code></p>';
        return err;
    }
    var rows = '';
    rows += field('TXT record', '<code>' + esc(data.sts_record) + '</code>');
    rows += field('Policy URL', '<code>' + esc(data.policy_url) + '</code>');
    var policy = data.policy || {};
    if (policy.version) rows += field('Version', '<code>' + esc(policy.version) + '</code>');
    if (policy.mode) {
        var modeCls = policy.mode === 'enforce' ? 'tag-ok'
                    : policy.mode === 'testing' ? 'tag-warn' : 'muted';
        rows += field('Mode', '<span class="' + modeCls + '">' + esc(policy.mode) + '</span>');
    }
    if (policy.max_age) rows += field('Max age', esc(policy.max_age) + ' seconds');
    if (policy.mx && policy.mx.length) {
        rows += field('MX hosts', policy.mx.map(function (m) { return '<code>' + esc(m) + '</code>'; }).join('<br>'));
    }
    var html = '<table>' + rows + '</table>';
    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list">'
            + data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('')
            + '</ul>';
    }
    return html;
}

function renderTLSRPT(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var rows = '';
    rows += field('TXT record', '<code>' + esc(data.record) + '</code>');
    var rua = data.rua || [];
    rows += field('rua',
        rua.length
            ? rua.map(function (r) { return '<code>' + esc(r) + '</code>'; }).join('<br>')
            : '<span class="tag-warn">none</span>');
    var html = '<table>' + rows + '</table>';
    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list">'
            + data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('')
            + '</ul>';
    }
    return html;
}

function renderBIMI(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var rows = '';
    rows += field('TXT record', '<code>' + esc(data.record) + '</code>');
    var tags = data.tags || {};
    Object.keys(tags).forEach(function (k) {
        rows += field(k, '<code>' + esc(tags[k]) + '</code>');
    });
    var logo = data.logo;
    if (logo) {
        var cell = '<code>' + esc(logo.url) + '</code> — ';
        if (logo.status == null) {
            cell += '<span class="tag-warn">' + esc(logo.content_type) + '</span>';
        } else if (logo.ok) {
            cell += '<span class="tag-ok">' + logo.status + ' ' + esc(logo.content_type || '') + '</span>';
        } else {
            cell += '<span class="tag-bad">' + logo.status + ' ' + esc(logo.content_type || '') + '</span>';
        }
        rows += field('Logo', cell);
    } else {
        rows += field('Logo', '<span class="tag-warn">l= is not set</span>');
    }
    var html = '<table>' + rows + '</table>';
    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list">'
            + data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('')
            + '</ul>';
    }
    return html;
}

function renderRoleAccounts(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var missing = data.missing_required || [];
    var html = missing.length
        ? statusDiv('red', 'Missing required role account(s): ' + missing.join(', '))
        : statusDiv('green', 'postmaster and abuse exist');
    html += '<p><b>MX host:</b> <code>' + esc(data.mx_host) + '</code></p>';
    html += '<table><thead><tr>'
          + '<th>Role</th><th>Address</th><th>RCPT code</th><th>Exists</th><th>Detail</th>'
          + '</tr></thead><tbody>';
    (data.results || []).forEach(function (r) {
        var detail = r.error ? r.error : (r.message || '');
        var isRequired = r.role === 'postmaster' || r.role === 'abuse';
        html += '<tr>'
            + '<td>' + esc(r.role) + (isRequired ? ' <span class="muted">(required)</span>' : '') + '</td>'
            + '<td><code>' + esc(r.address) + '</code></td>'
            + '<td>' + (r.code != null ? r.code : '—') + '</td>'
            + '<td>' + boolTag(r.exists) + '</td>'
            + '<td><code>' + esc(detail) + '</code></td>'
            + '</tr>';
    });
    html += '</tbody></table>';
    return html;
}

function renderCatchAll(data) {
    if (!data.valid) return statusDiv('red', data.error || 'lookup failed');
    var html = data.catch_all
        ? statusDiv('orange', 'Catch-all is enabled — random address accepted')
        : statusDiv('green', 'No catch-all — random address rejected');
    var rows = '';
    rows += field('MX host', '<code>' + esc(data.mx_host) + '</code>');
    rows += field('Probe address', '<code>' + esc(data.probe_address) + '</code>');
    rows += field('RCPT code', data.rcpt_code != null ? data.rcpt_code : '—');
    if (data.rcpt_message) rows += field('RCPT message', '<code>' + esc(data.rcpt_message) + '</code>');
    html += '<table>' + rows + '</table>';
    if (data.warnings && data.warnings.length) {
        html += '<ul class="err-list">'
            + data.warnings.map(function (w) { return '<li class="warn">' + esc(w) + '</li>'; }).join('')
            + '</ul>';
    }
    return html;
}

function renderSingle(key, data) {
    switch (key) {
        case 'spf': return renderSPF(data);
        case 'dmarc': return renderDMARC(data);
        case 'dkim': return renderDKIM(data);
        case 'mx': return renderMX(data);
        case 'blacklist': return renderBlacklist(data);
        case 'smtp': return renderSMTP(data);
        case 'mailbox': return renderMailbox(data);
        case 'ptr': return renderPTR(data);
        case 'tls-cert': return renderTLSCert(data);
        case 'mta-sts': return renderMTASTS(data);
        case 'tls-rpt': return renderTLSRPT(data);
        case 'bimi': return renderBIMI(data);
        case 'role-accounts': return renderRoleAccounts(data);
        case 'catch-all': return renderCatchAll(data);
        default: return '<pre>' + esc(JSON.stringify(data, null, 2)) + '</pre>';
    }
}

const STATUS_LABEL = { pass: "PASS", warn: "WARN", fail: "FAIL", info: "INFO" };

function statusClass(s) {
    if (s === "pass") return "tag-ok";
    if (s === "fail") return "tag-bad";
    if (s === "warn") return "tag-warn";
    return "muted";
}

function renderFull(data) {
    if (data.error) return statusDiv('red', data.error);

    var s = data.summary;
    var kind = s.passed === s.total
        ? 'green'
        : s.passed >= s.total - 1 ? 'orange' : 'red';

    var html = statusDiv(
        kind,
        s.score + ' critical checks passed (SPF / DMARC / DKIM / MX / Blacklist)'
    );

    html += '<p><b>Domain:</b> ' + esc(data.domain);
    if (data.email) html += ' &middot; <b>Email:</b> ' + esc(data.email);
    html += '</p>';

    html += '<table><thead><tr>'
          + '<th>Check</th><th>Status</th><th>Detail</th>'
          + '</tr></thead><tbody>';
    data.checks.forEach(function (c) {
        var cls = statusClass(c.status);
        var label = STATUS_LABEL[c.status] || String(c.status).toUpperCase();
        var note = c.scoring ? '' : ' <span class="muted">(info)</span>';
        html += '<tr>'
            + '<td>' + esc(c.label) + note + '</td>'
            + '<td><span class="' + cls + '">' + label + '</span></td>'
            + '<td>' + esc(c.detail || '') + '</td>'
            + '</tr>';
    });
    html += '</tbody></table>';

    html += '<div class="verify-details">';
    data.checks.forEach(function (c) {
        html += '<h3>' + esc(c.label);
        if (!c.scoring) html += ' <span class="muted">(informational)</span>';
        html += '</h3>';
        html += renderSingle(c.key, c.result);
    });
    html += '</div>';
    return html;
}

/* ---------- Payload per tool ---------- */
function collectPayload(tool) {
    function val(id) {
        var el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }
    switch (tool) {
        case 'full': return { domain: val('fullInput') };
        case 'spf': return { domain: val('spfInput') };
        case 'dmarc': return { domain: val('dmarcInput') };
        case 'dkim': return { domain: val('dkimInput'), selector: val('dkimSelector') };
        case 'mx': return { domain: val('mxInput') };
        case 'blacklist': return { domain: val('blacklistInput') };
        case 'smtp': return { domain: val('smtpInput') };
        case 'mailbox': return { email: val('mailboxInput'), server: val('mailboxServer') };
        case 'ptr': return { domain: val('ptrInput') };
        case 'tls-cert': return { domain: val('tls-certInput') };
        case 'mta-sts': return { domain: val('mta-stsInput') };
        case 'tls-rpt': return { domain: val('tls-rptInput') };
        case 'bimi': return { domain: val('bimiInput') };
        case 'role-accounts': return { domain: val('role-accountsInput') };
        case 'catch-all': return { domain: val('catch-allInput') };
        default: return {};
    }
}

/* ---------- Submit handler ---------- */
document.querySelectorAll('.run-btn').forEach(function (btn) {
    btn.addEventListener('click', async function () {
        var tool = btn.dataset.tool;
        var section = btn.closest('section');
        var resultStep = section.querySelectorAll('.step')[1];
        var resultEl = section.querySelector('#result-' + tool);
        var input = section.querySelector('input[type="text"]');

        if (input && !input.value.trim()) {
            input.focus();
            return;
        }

        resultStep.style.display = '';
        resultEl.innerHTML = '<span class="muted">running ' + esc(tool) + '…</span>';
        btn.disabled = true;

        try {
            var resp = await fetch('/api/' + tool, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(collectPayload(tool))
            });
            var data = await resp.json();

            if (tool === 'full') resultEl.innerHTML = renderFull(data);
            else if (tool === 'mailbox') resultEl.innerHTML = renderMailbox(data);
            else resultEl.innerHTML = renderSingle(tool, data);

            if (!resp.ok) {
                resultEl.innerHTML = statusDiv('red', data.error || 'request failed') + resultEl.innerHTML;
            }
        } catch (e) {
            resultEl.innerHTML = statusDiv('red', 'Network error: ' + e.message);
        } finally {
            btn.disabled = false;
        }
    });
});

/* Re-apply theme when system preference changes (only if user is on 'auto') */
if (window.matchMedia) {
    try {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
            var pref = 'auto';
            try { pref = localStorage.getItem('mx_tools_theme') || 'auto'; } catch (e) {}
            if (pref === 'auto') applyTheme('auto');
        });
    } catch (e) {}
}
