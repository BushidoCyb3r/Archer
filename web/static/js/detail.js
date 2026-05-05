// detail.js — detail pane renderer
'use strict';

const Detail = (() => {
  const EXPLANATIONS = window.SCORE_EXPLANATIONS || {};

  function _sevColor(sev) {
    return {CRITICAL:'var(--sev-critical)', HIGH:'var(--sev-high)', MEDIUM:'var(--sev-medium)',
            LOW:'var(--sev-low)', INFO:'var(--sev-info)', IOC_HIT:'var(--ioc-color)'}[sev] || 'var(--fg-text)';
  }

  function _statusLabel(s) {
    if (s === 'acknowledged') return 'ACKNOWLEDGED';
    if (s === 'escalated')    return 'ESCALATED';
    return 'OPEN';
  }

  function render(f) {
    const header = document.getElementById('detail-header');
    const text   = document.getElementById('detail-text');
    const rec    = document.getElementById('analyst-rec');

    const dst    = f.dst_ip || '—';
    const sensor = f.sensor || '';
    header.textContent = `${f.type}  [${f.severity}  score ${f.score}]  ${f.src_ip || '—'} → ${dst}${f.dst_port ? ':' + f.dst_port : ''}`;
    header.style.color = _sevColor(f.severity);

    const lines = [];
    lines.push(`Type       : ${f.type}`);
    lines.push(`Severity   : ${f.severity}   Score: ${f.score}`);
    lines.push(`Status     : ${_statusLabel(f.status)}`);
    if (sensor) lines.push(`Sensor     : ${sensor}`);
    lines.push(`Timestamp  : ${f.timestamp || '—'}`);
    lines.push(`Source     : ${f.source_file || '—'}`);
    lines.push('');
    if (f.src_ip)   lines.push(`Src IP     : ${f.src_ip}`);
    if (f.dst_ip)   lines.push(`Dst IP     : ${f.dst_ip}`);
    if (f.dst_port) lines.push(`Dst Port   : ${f.dst_port}`);
    lines.push('');
    if (f.detail)   lines.push(f.detail);
    if (f.is_new)   { lines.push(''); lines.push('*** NEW SINCE BASELINE ***'); }
    if (f.ioc_match){ lines.push(''); lines.push('*** MATCHED IOC LIST ***'); }
    if (f.status === 'escalated') {
      lines.push('');
      lines.push(`Escalated  : ${f.status_ts || '—'}`);
      if (f.analyst) lines.push(`Analyst    : ${f.analyst}`);
    }
    if (f.analyst_note) {
      lines.push('');
      lines.push('Analyst Note:');
      lines.push(f.analyst_note);
    }

    const explain = EXPLANATIONS[f.type] || '';
    if (explain) {
      lines.push('');
      lines.push('Why flagged:');
      lines.push(explain);
    }

    text.textContent = lines.join('\n');
    rec.textContent = explain ? explain.split('.')[0] : '';

    // Action buttons
    const ackBtn   = document.getElementById('ack-btn');
    const escBtn   = document.getElementById('esc-btn');
    const chartBtn = document.getElementById('chart-btn');
    const pcapBtn  = document.getElementById('pcap-btn');
    const rawBtn   = document.getElementById('raw-btn');
    const suppBtn  = document.getElementById('supp-btn');

    ackBtn.disabled  = false;
    escBtn.disabled  = f.status === 'escalated';
    suppBtn.disabled = false;
    pcapBtn.disabled = !(f.src_ip && f.dst_ip);
    chartBtn.disabled = !(f.ts_data && f.ts_data.length > 0);
    if (rawBtn) {
      rawBtn.disabled = !(f.src_ip && f.dst_ip);
      rawBtn.dataset.findingId = f.id;
    }

    ackBtn.textContent = f.status === 'acknowledged' ? 'Acknowledged' : 'Acknowledge';

    // Notes
    _renderNotes(f);
  }

  function _renderNotes(f) {
    const section = document.getElementById('notes-section');
    const list    = document.getElementById('notes-list');
    section.style.display = 'block';
    list.innerHTML = '';
    const notes = f.notes || [];
    if (notes.length === 0) {
      list.innerHTML = '<div style="font-size:11px;color:var(--fg-dim);font-style:italic">No notes yet</div>';
    } else {
      notes.forEach(n => {
        const div = document.createElement('div');
        div.className = 'note-item';
        div.innerHTML = `
          <div class="note-meta"><span class="note-author">${_esc(n.author)}</span>  •  ${_esc(n.timestamp)}</div>
          <div class="note-text">${_esc(n.text)}</div>`;
        list.appendChild(div);
      });
    }
  }

  function _esc(s) {
    return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function clear() {
    document.getElementById('detail-header').textContent = 'SELECT A FINDING';
    document.getElementById('detail-header').style.color = '';
    document.getElementById('detail-text').textContent = '';
    document.getElementById('analyst-rec').textContent = '';
    document.getElementById('notes-section').style.display = 'none';
    document.getElementById('notes-list').innerHTML = '';
    ['ack-btn','esc-btn','chart-btn','pcap-btn','supp-btn'].forEach(id => {
      document.getElementById(id).disabled = true;
    });
  }

  return { render, clear };
})();
