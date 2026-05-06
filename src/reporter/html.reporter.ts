import fs from 'fs';
import path from 'path';
import dayjs from 'dayjs';
import { Finding, ScanResult, Severity } from '../types';

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#e53e3e',
  high: '#dd6b20',
  medium: '#d69e2e',
  low: '#38a169',
  info: '#3182ce',
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: '#fff5f5',
  high: '#fffaf0',
  medium: '#fffff0',
  low: '#f0fff4',
  info: '#ebf8ff',
};

export class HtmlReporter {
  generate(result: ScanResult, outputDir: string): string {
    fs.mkdirSync(outputDir, { recursive: true });

    const slug = result.target.name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '-')
      .replace(/-+/g, '-');
    const date = dayjs(result.startedAt).format('YYYY-MM-DD_HH-mm');
    const filename = `${slug}_${date}.html`;
    const filepath = path.join(outputDir, filename);

    const html = this.buildHtml(result);
    fs.writeFileSync(filepath, html, 'utf-8');
    return filepath;
  }

  private buildHtml(result: ScanResult): string {
    const { target, findings, startedAt, finishedAt, passed } = result;

    const duration = this.calcDuration(startedAt, finishedAt);
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;

    const findingsHtml = findings.length
      ? findings.map((f, i) => this.buildFindingCard(f, i + 1)).join('\n')
      : `<div class="no-findings">
           <div class="no-findings-icon">✓</div>
           <p>No vulnerabilities detected in this scan.</p>
         </div>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CVEBox Report — ${this.esc(target.name)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f7fafc; color: #2d3748; }

    .header { background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: white; padding: 32px 40px; }
    .header-top { display: flex; align-items: center; gap: 16px; margin-bottom: 8px; }
    .logo { font-size: 28px; font-weight: 800; letter-spacing: -1px; color: #fc8181; }
    .logo span { color: white; }
    .header h1 { font-size: 22px; font-weight: 600; opacity: 0.9; }
    .header-meta { font-size: 13px; opacity: 0.6; margin-top: 4px; }
    .header-meta a { color: #90cdf4; text-decoration: none; }

    .status-bar { display: flex; gap: 0; }
    .status-pill { padding: 6px 20px; font-size: 13px; font-weight: 700; letter-spacing: 0.5px; border-radius: 0; }
    .status-pill.pass { background: #276749; color: #c6f6d5; }
    .status-pill.fail { background: #742a2a; color: #fed7d7; }

    .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .summary-card { background: white; border-radius: 8px; padding: 20px 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .summary-card .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.8px; color: #718096; margin-bottom: 6px; }
    .summary-card .value { font-size: 28px; font-weight: 700; }
    .summary-card .value.critical { color: #e53e3e; }
    .summary-card .value.high { color: #dd6b20; }
    .summary-card .value.medium { color: #d69e2e; }
    .summary-card .value.ok { color: #38a169; }

    .section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; color: #1a202c; border-left: 4px solid #4299e1; padding-left: 12px; }

    .finding-card { background: white; border-radius: 8px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; border-left: 5px solid; }
    .finding-header { display: flex; align-items: flex-start; justify-content: space-between; padding: 16px 20px 12px; cursor: pointer; }
    .finding-header:hover { background: #f7fafc; }
    .finding-title { display: flex; align-items: center; gap: 10px; }
    .severity-badge { font-size: 11px; font-weight: 700; letter-spacing: 0.5px; padding: 3px 10px; border-radius: 20px; text-transform: uppercase; }
    .finding-name { font-size: 15px; font-weight: 600; }
    .finding-meta { font-size: 12px; color: #718096; margin-top: 3px; }
    .cve-link { font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 4px; text-decoration: none; background: #ebf8ff; color: #2b6cb0; border: 1px solid #bee3f8; white-space: nowrap; }
    .cve-link:hover { background: #bee3f8; }

    .finding-body { padding: 0 20px 20px; display: none; }
    .finding-body.open { display: block; }

    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
    .detail-item { background: #f7fafc; border-radius: 6px; padding: 10px 14px; }
    .detail-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: #718096; margin-bottom: 4px; }
    .detail-value { font-size: 13px; font-family: 'Courier New', monospace; word-break: break-all; }

    .section-block { margin-top: 12px; }
    .section-block .block-label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #4a5568; margin-bottom: 6px; }
    .code-block { background: #1a202c; color: #e2e8f0; border-radius: 6px; padding: 12px 16px; font-family: 'Courier New', monospace; font-size: 12px; word-break: break-all; line-height: 1.6; }
    .evidence-block { background: #fff5f5; border: 1px solid #fed7d7; border-radius: 6px; padding: 12px 16px; font-size: 13px; color: #742a2a; line-height: 1.6; }
    .remediation-block { background: #f0fff4; border: 1px solid #c6f6d5; border-radius: 6px; padding: 12px 16px; font-size: 13px; color: #276749; line-height: 1.6; }

    .no-findings { text-align: center; padding: 64px 24px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .no-findings-icon { font-size: 48px; color: #38a169; margin-bottom: 12px; }
    .no-findings p { color: #718096; font-size: 16px; }

    .screenshot-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 12px; }
    .screenshot-box { background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; overflow: hidden; }
    .screenshot-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; padding: 8px 12px; display: flex; align-items: center; gap: 6px; }
    .screenshot-label.before { background: #ebf8ff; color: #2b6cb0; border-bottom: 1px solid #bee3f8; }
    .screenshot-label.after  { background: #fff5f5; color: #c53030; border-bottom: 1px solid #fed7d7; }
    .screenshot-img { width: 100%; display: block; cursor: zoom-in; transition: opacity 0.15s; }
    .screenshot-img:hover { opacity: 0.92; }

    /* Lightbox */
    .lb-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 9999; justify-content: center; align-items: center; }
    .lb-overlay.open { display: flex; }
    .lb-overlay img { max-width: 92vw; max-height: 90vh; border-radius: 6px; box-shadow: 0 8px 40px rgba(0,0,0,0.5); }
    .lb-close { position: fixed; top: 16px; right: 24px; color: white; font-size: 32px; cursor: pointer; line-height: 1; }

    .target-info { background: white; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
    .target-info table { width: 100%; border-collapse: collapse; }
    .target-info td { padding: 6px 0; font-size: 13px; vertical-align: top; }
    .target-info td:first-child { color: #718096; width: 160px; }
    .target-info td:last-child { font-weight: 500; word-break: break-all; }

    .footer { text-align: center; padding: 24px; color: #a0aec0; font-size: 12px; }

    @media (max-width: 600px) {
      .detail-grid { grid-template-columns: 1fr; }
      .summary-grid { grid-template-columns: 1fr 1fr; }
    }
  </style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">CVE<span>Box</span></div>
    <div>
      <h1>Security Scan Report — ${this.esc(target.name)}</h1>
      <div class="header-meta">
        Generated on ${dayjs(startedAt).format('MMMM D, YYYY [at] HH:mm:ss')} · Duration: ${duration}
      </div>
    </div>
  </div>
  <div class="status-bar">
    <span class="status-pill ${passed ? 'pass' : 'fail'}">${passed ? '✓ PASSED — No vulnerabilities found' : `✗ FAILED — ${findings.length} vulnerability finding(s)`}</span>
  </div>
</div>

<div class="container">

  <div class="target-info">
    <table>
      <tr><td>Target Name</td><td>${this.esc(target.name)}</td></tr>
      <tr><td>URL</td><td><a href="${this.esc(target.url)}" target="_blank">${this.esc(target.url)}</a></td></tr>
      <tr><td>Login URL</td><td>${target.loginUrl ? `<a href="${this.esc(target.loginUrl)}" target="_blank">${this.esc(target.loginUrl)}</a>` : '—'}</td></tr>
      <tr><td>Scan Started</td><td>${dayjs(startedAt).format('YYYY-MM-DD HH:mm:ss')}</td></tr>
      <tr><td>Scan Finished</td><td>${dayjs(finishedAt).format('YYYY-MM-DD HH:mm:ss')}</td></tr>
      <tr><td>Duration</td><td>${duration}</td></tr>
    </table>
  </div>

  <div class="summary-grid">
    <div class="summary-card">
      <div class="label">Total Findings</div>
      <div class="value ${findings.length > 0 ? 'critical' : 'ok'}">${findings.length}</div>
    </div>
    <div class="summary-card">
      <div class="label">Critical</div>
      <div class="value critical">${critical}</div>
    </div>
    <div class="summary-card">
      <div class="label">High</div>
      <div class="value high">${high}</div>
    </div>
    <div class="summary-card">
      <div class="label">Medium</div>
      <div class="value medium">${medium}</div>
    </div>
    <div class="summary-card">
      <div class="label">Plugins Tested</div>
      <div class="value ok">${result.totalTested}</div>
    </div>
  </div>

  <div class="section-title">Vulnerability Findings</div>
  ${findingsHtml}

</div>

<div class="footer">
  CVEBox · Automated Security Scanner · Report for <strong>${this.esc(target.name)}</strong> · ${dayjs(startedAt).format('YYYY-MM-DD')}
</div>

<!-- Lightbox overlay for full-size screenshots -->
<div class="lb-overlay" id="lb-overlay">
  <span class="lb-close" onclick="closeLightbox()">&#x2715;</span>
  <img id="lb-img" src="" alt="Screenshot" />
</div>

<script>
  document.querySelectorAll('.finding-header').forEach(function(header) {
    header.addEventListener('click', function() {
      var body = this.nextElementSibling;
      body.classList.toggle('open');
    });
  });

  function openLightbox(src) {
    document.getElementById('lb-img').src = src;
    document.getElementById('lb-overlay').classList.add('open');
  }
  function closeLightbox() {
    document.getElementById('lb-overlay').classList.remove('open');
    document.getElementById('lb-img').src = '';
  }
  document.getElementById('lb-overlay').addEventListener('click', function(e) {
    if (e.target === this) closeLightbox();
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeLightbox();
  });
</script>
</body>
</html>`;
  }

  private buildFindingCard(f: Finding, index: number): string {
    const color = SEVERITY_COLOR[f.severity] || '#718096';
    const bg = SEVERITY_BG[f.severity] || '#f7fafc';

    return `
<div class="finding-card" style="border-left-color: ${color}; background: ${bg}10;">
  <div class="finding-header">
    <div class="finding-title">
      <span class="severity-badge" style="background: ${color}20; color: ${color};">${f.severity}</span>
      <div>
        <div class="finding-name">#${index} — ${this.esc(f.pluginName)}</div>
        <div class="finding-meta">Field: <code>${this.esc(f.field)}</code> · Surface: ${this.esc(f.surface)} · ${dayjs(f.timestamp).format('HH:mm:ss')}</div>
      </div>
    </div>
    <a class="cve-link" href="${this.esc(f.cveUrl)}" target="_blank" onclick="event.stopPropagation()">
      ${this.esc(f.cveId)} ↗
    </a>
  </div>
  <div class="finding-body">
    <div class="detail-grid">
      <div class="detail-item">
        <div class="detail-label">CVE / CWE Reference</div>
        <div class="detail-value"><a href="${this.esc(f.cveUrl)}" target="_blank">${this.esc(f.cveId)}</a></div>
      </div>
      <div class="detail-item">
        <div class="detail-label">Severity</div>
        <div class="detail-value" style="color: ${color}; font-weight: 700;">${f.severity.toUpperCase()}</div>
      </div>
      <div class="detail-item">
        <div class="detail-label">Attack Surface</div>
        <div class="detail-value">${this.esc(f.surface)}</div>
      </div>
      <div class="detail-item">
        <div class="detail-label">Affected Field / Endpoint</div>
        <div class="detail-value">${this.esc(f.field)}</div>
      </div>
    </div>

    <div class="section-block">
      <div class="block-label">Description</div>
      <div style="font-size: 13px; color: #4a5568; line-height: 1.6;">${this.esc(f.description)}</div>
    </div>

    <div class="section-block">
      <div class="block-label">Injected Payload</div>
      <div class="code-block">${this.esc(f.payload)}</div>
    </div>

    <div class="section-block">
      <div class="block-label">Evidence</div>
      <div class="evidence-block">${this.esc(f.evidence)}</div>
    </div>

    <div class="section-block">
      <div class="block-label">Recommended Fix</div>
      <div class="remediation-block">${this.esc(f.remediation)}</div>
    </div>

    ${this.buildScreenshots(f)}
  </div>
</div>`;
  }

  private buildScreenshots(f: Finding): string {
    const hasBefore = f.screenshotBefore && f.screenshotBefore.length > 0;
    const hasAfter = f.screenshotAfter && f.screenshotAfter.length > 0;
    if (!hasBefore && !hasAfter) return '';

    const beforeHtml = hasBefore
      ? `<div class="screenshot-box">
           <div class="screenshot-label before">📷 Before Injection — Page state before payload was sent</div>
           <img class="screenshot-img" src="data:image/png;base64,${f.screenshotBefore}"
                alt="Before injection" onclick="openLightbox(this.src)" />
         </div>`
      : '';

    const afterHtml = hasAfter
      ? `<div class="screenshot-box">
           <div class="screenshot-label after">🔴 After Injection — Response / evidence captured</div>
           <img class="screenshot-img" src="data:image/png;base64,${f.screenshotAfter}"
                alt="After injection — evidence" onclick="openLightbox(this.src)" />
         </div>`
      : '';

    return `
    <div class="section-block">
      <div class="block-label">Visual Evidence — Click any screenshot to enlarge</div>
      <div class="screenshot-grid">
        ${beforeHtml}
        ${afterHtml}
      </div>
    </div>`;
  }

  private esc(str: string): string {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private calcDuration(start: string, end: string): string {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    if (m > 0) return `${m}m ${s % 60}s`;
    return `${s}s`;
  }
}
