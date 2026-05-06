import path from 'path';
import { BasePlugin } from './base.plugin';
import { Finding, Payload, PluginContext } from '../types';
import { FormSurface } from '../surfaces/form.surface';
import { QueryParamSurface } from '../surfaces/query-param.surface';
import { HeaderSurface } from '../surfaces/header.surface';
import { takeScreenshot } from '../core/screenshot';

const XSS_MARKER = 'CVEBox-XSS';

const REMEDIATION =
  'Encode all user-controlled output using context-aware encoding (HTML, JS, URL). ' +
  'Implement a strict Content Security Policy (CSP). ' +
  'Use DOMPurify or similar libraries for client-side HTML sanitization. ' +
  'Reference: https://owasp.org/www-community/attacks/xss/';

export class XssPlugin extends BasePlugin {
  readonly id = 'xss' as const;
  readonly name = 'Cross-Site Scripting (XSS)';
  readonly description =
    'Tests for Reflected, Stored, and DOM-based XSS vulnerabilities in forms, query parameters, and headers';

  loadPayloads(): void {
    this.payloads = require(
      path.join(__dirname, '../patterns/xss/payloads.json')
    ) as Payload[];
  }

  async run(ctx: PluginContext): Promise<Finding[]> {
    this.loadPayloads();
    const findings: Finding[] = [];

    if (ctx.surfaces.includes('form')) {
      const formSurface = new FormSurface(ctx.page);
      const fields = await formSurface.discoverFields();

      for (const field of fields) {
        for (const payload of this.payloads) {
          try {
            const screenshotBefore = await takeScreenshot(ctx.page);
            const result = await formSurface.inject(field, payload.value);

            if (result.includes(XSS_MARKER) || result.includes('<script>') || result.includes('onerror=')) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'form', field.name,
                  `XSS payload reflected unescaped in response after injecting into "${field.name}". Payload: ${payload.value}`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
            }

            const dialogTriggered = await this.checkDialogTriggered(ctx);
            if (dialogTriggered) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'form', field.name,
                  `XSS payload triggered a JavaScript dialog (alert/confirm/prompt) in field "${field.name}". Payload: ${payload.value}`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
            }
          } catch {
            // continue
          }
        }
      }
    }

    if (ctx.surfaces.includes('query-param')) {
      const qpSurface = new QueryParamSurface(ctx.page);
      const params = await qpSurface.discoverParams(ctx.target.url);

      for (const param of params) {
        for (const payload of this.payloads) {
          try {
            const screenshotBefore = await takeScreenshot(ctx.page);
            const result = await qpSurface.inject(ctx.target.url, param, payload.value);
            if (result.includes(XSS_MARKER) || result.includes('<script>')) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'query-param', param,
                  `XSS payload reflected in query param "${param}" response. Payload: ${payload.value}`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
            }
          } catch {
            // continue
          }
        }
      }
    }

    if (ctx.surfaces.includes('header')) {
      const headerSurface = new HeaderSurface(ctx.page);

      for (const payload of this.payloads) {
        try {
          const screenshotBefore = await takeScreenshot(ctx.page);
          const result = await headerSurface.inject(ctx.target.url, 'X-Forwarded-For', payload.value);
          if (result.includes(XSS_MARKER)) {
            const screenshotAfter = await takeScreenshot(ctx.page);
            findings.push(
              this.createFinding(
                ctx, payload, 'header', 'X-Forwarded-For',
                `XSS payload reflected from X-Forwarded-For header. Payload: ${payload.value}`,
                REMEDIATION, screenshotBefore, screenshotAfter
              )
            );
          }
        } catch {
          // continue
        }
      }
    }

    return findings;
  }

  private async checkDialogTriggered(ctx: PluginContext): Promise<boolean> {
    try {
      const dialogPromise = new Promise<boolean>((resolve) => {
        const handler = () => {
          ctx.page.removeListener('dialog', handler);
          resolve(true);
        };
        ctx.page.once('dialog', handler);
        setTimeout(() => {
          ctx.page.removeListener('dialog', handler);
          resolve(false);
        }, 1500);
      });
      return await dialogPromise;
    } catch {
      return false;
    }
  }
}
