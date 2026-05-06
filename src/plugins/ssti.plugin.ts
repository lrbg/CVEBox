import path from 'path';
import { BasePlugin } from './base.plugin';
import { Finding, Payload, PluginContext } from '../types';
import { FormSurface } from '../surfaces/form.surface';
import { QueryParamSurface } from '../surfaces/query-param.surface';
import { takeScreenshot } from '../core/screenshot';

const SSTI_PROBE_RESULT = '49';

const SSTI_ERROR_PATTERNS = [
  'templateerror',
  'jinja2',
  'freemarker',
  'velocity',
  'thymeleaf',
  'erb',
  'pebble',
  'template rendering',
  'parsing error',
  'expression evaluation',
  'spel',
];

const REMEDIATION =
  'Never pass user-controlled input directly to template engines. ' +
  'Use a sandboxed template environment with no access to Python/Java/Ruby internals. ' +
  'Validate and sanitize all inputs before rendering. ' +
  'Reference: https://owasp.org/www-community/attacks/Server_Side_Template_Injection';

export class SstiPlugin extends BasePlugin {
  readonly id = 'ssti' as const;
  readonly name = 'Server-Side Template Injection (SSTI)';
  readonly description =
    'Tests for SSTI vulnerabilities in Jinja2, FreeMarker, Thymeleaf, Spring SpEL, ERB and other template engines';

  loadPayloads(): void {
    this.payloads = require(
      path.join(__dirname, '../patterns/ssti/payloads.json')
    ) as Payload[];
  }

  async run(ctx: PluginContext): Promise<Finding[]> {
    this.loadPayloads();
    const findings: Finding[] = [];

    if (ctx.surfaces.includes('form')) {
      const formSurface = new FormSurface(ctx.page);
      const fields = await formSurface.discoverFields();

      for (const field of fields) {
        const screenshotBefore = await takeScreenshot(ctx.page);
        for (const payload of this.payloads) {
          try {
            const result = await formSurface.inject(field, payload.value);
            const isVuln =
              result.includes(SSTI_PROBE_RESULT) ||
              this.isVulnerableResponse(result, SSTI_ERROR_PATTERNS);

            if (isVuln) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'form', field.name,
                  `SSTI probe evaluated: payload "${payload.value}" produced output containing "${SSTI_PROBE_RESULT}" or template error in field "${field.name}"`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
              break;
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
        const screenshotBefore = await takeScreenshot(ctx.page);
        for (const payload of this.payloads) {
          try {
            const result = await qpSurface.inject(ctx.target.url, param, payload.value);
            const isVuln =
              result.includes(SSTI_PROBE_RESULT) ||
              this.isVulnerableResponse(result, SSTI_ERROR_PATTERNS);

            if (isVuln) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'query-param', param,
                  `SSTI probe evaluated in query param "${param}": "${payload.value}" → "${SSTI_PROBE_RESULT}" found in response`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
              break;
            }
          } catch {
            // continue
          }
        }
      }
    }

    return findings;
  }
}
