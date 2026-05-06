import chalk from 'chalk';
import { BrowserManager } from './browser';
import { authenticate, validateSession } from './auth';
import { getPlugins } from '../plugins/registry';
import { Finding, PluginId, ScanOptions, ScanResult, SurfaceType, Target } from '../types';

export class Scanner {
  private browser: BrowserManager;

  constructor() {
    this.browser = new BrowserManager();
  }

  async scan(target: Target, options: ScanOptions): Promise<ScanResult> {
    const startedAt = new Date().toISOString();
    const findings: Finding[] = [];
    let totalTested = 0;

    console.log(chalk.cyan(`\n  [TARGET] ${target.name} → ${target.url}`));

    await this.browser.launch({ headed: options.headed, timeout: options.timeout });
    const page = await this.browser.newPage();

    try {
      // Authentication
      if (target.username || target.password) {
        console.log(chalk.yellow('  [AUTH] Authenticating...'));
        const authResult = await authenticate(page, target);

        if (!authResult.success) {
          console.log(chalk.red(`  [AUTH] FAILED: ${authResult.errorMessage}`));
          console.log(chalk.yellow('  [WARN] Proceeding without authentication.'));
        } else {
          console.log(chalk.green('  [AUTH] Authentication successful'));
        }
      } else {
        console.log(chalk.gray('  [AUTH] No credentials provided, skipping auth'));
        await page.goto(target.url, { waitUntil: 'networkidle', timeout: 15000 });
      }

      // Navigate to target URL
      const currentUrl = page.url();
      if (currentUrl !== target.url) {
        await page.goto(target.url, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
      }

      const sessionValid = await validateSession(page);
      if (!sessionValid && (target.username || target.password)) {
        console.log(chalk.yellow('  [SESSION] Session validation inconclusive, continuing...'));
      }

      // Run selected plugins
      const plugins = getPlugins(options.plugins);
      const surfaces: SurfaceType[] = options.surfaces.length
        ? options.surfaces
        : ['form', 'query-param', 'header', 'api-body'];

      for (const plugin of plugins) {
        console.log(chalk.blue(`\n  [SCAN] Running plugin: ${plugin.name}`));

        const ctx = { target, page, surfaces };
        const pluginFindings = await plugin.run(ctx);
        totalTested += 1;

        if (pluginFindings.length > 0) {
          console.log(
            chalk.red(`  [!] ${pluginFindings.length} finding(s) detected by ${plugin.name}`)
          );
          for (const f of pluginFindings) {
            const severityColor = this.severityColor(f.severity);
            console.log(
              `      ${severityColor(`[${f.severity.toUpperCase()}]`)} ${f.cveId} — ${f.field} (${f.surface})`
            );
          }
          findings.push(...pluginFindings);
        } else {
          console.log(chalk.green(`  [OK] No findings from ${plugin.name}`));
        }
      }
    } finally {
      await this.browser.close();
    }

    const finishedAt = new Date().toISOString();
    const passed = findings.length === 0;

    console.log('\n');
    if (passed) {
      console.log(chalk.green('  [RESULT] No vulnerabilities detected.'));
    } else {
      console.log(
        chalk.red(`  [RESULT] ${findings.length} vulnerability finding(s) detected!`)
      );
    }

    return { target, startedAt, finishedAt, findings, totalTested, passed };
  }

  private severityColor(severity: string): (text: string) => string {
    switch (severity) {
      case 'critical': return chalk.bgRed.white;
      case 'high': return chalk.red;
      case 'medium': return chalk.yellow;
      default: return chalk.gray;
    }
  }
}
