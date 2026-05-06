import path from 'path';
import { BasePlugin } from './base.plugin';
import { Finding, Payload, PluginContext } from '../types';
import { QueryParamSurface } from '../surfaces/query-param.surface';
import { ApiBodySurface } from '../surfaces/api-body.surface';
import { takeScreenshot } from '../core/screenshot';

const POLLUTION_MARKER = 'CVEBox';

const POLLUTION_ERROR_PATTERNS = [
  'prototype',
  '__proto__',
  'constructor',
  'typeerror',
  'cannot set property',
  'object object',
];

const REMEDIATION =
  'Use Object.create(null) for objects that should not inherit from Object.prototype. ' +
  'Validate JSON input using schema validation (e.g. Joi, Zod, Ajv). ' +
  'Freeze Object.prototype in Node.js apps. ' +
  'Use libraries like deep-merge-safe instead of vulnerable merge utilities. ' +
  'Reference: https://owasp.org/www-community/vulnerabilities/Prototype_Pollution';

export class PrototypePollutionPlugin extends BasePlugin {
  readonly id = 'prototype-pollution' as const;
  readonly name = 'Prototype Pollution';
  readonly description =
    'Tests for JavaScript prototype pollution via query params and JSON API bodies';

  loadPayloads(): void {
    this.payloads = require(
      path.join(__dirname, '../patterns/prototype-pollution/payloads.json')
    ) as Payload[];
  }

  async run(ctx: PluginContext): Promise<Finding[]> {
    this.loadPayloads();
    const findings: Finding[] = [];

    if (ctx.surfaces.includes('query-param')) {
      const qpSurface = new QueryParamSurface(ctx.page);
      const queryPayloads = this.payloads.filter(
        (p) => (p as any).surface === 'query-param'
      );

      for (const payload of queryPayloads) {
        try {
          const screenshotBefore = await takeScreenshot(ctx.page);
          const result = await qpSurface.injectRaw(ctx.target.url, payload.value);
          const isPolluted =
            result.includes(POLLUTION_MARKER) ||
            this.isVulnerableResponse(result, POLLUTION_ERROR_PATTERNS);

          if (isPolluted) {
            const screenshotAfter = await takeScreenshot(ctx.page);
            findings.push(
              this.createFinding(
                ctx, payload, 'query-param', '__proto__',
                `Prototype pollution detected via query param: ${payload.value}. Response contained pollution marker or error.`,
                REMEDIATION, screenshotBefore, screenshotAfter
              )
            );
          }
        } catch {
          // continue
        }
      }
    }

    if (ctx.surfaces.includes('api-body')) {
      const apiSurface = new ApiBodySurface(ctx.page);
      const endpoints = await apiSurface.discoverEndpoints();
      const bodyPayloads = this.payloads.filter(
        (p) => (p as any).surface === 'api-body'
      );

      for (const endpoint of endpoints) {
        for (const payload of bodyPayloads) {
          try {
            const screenshotBefore = await takeScreenshot(ctx.page);
            const result = await apiSurface.injectRaw(endpoint.url, endpoint.method, payload.value);
            const isPolluted =
              result.includes(POLLUTION_MARKER) ||
              this.isVulnerableResponse(result, POLLUTION_ERROR_PATTERNS);

            if (isPolluted) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'api-body', endpoint.url,
                  `Prototype pollution in API body for ${endpoint.method} ${endpoint.url}: ${payload.value}`,
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

    return findings;
  }
}
