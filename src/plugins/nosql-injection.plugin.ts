import path from 'path';
import { BasePlugin } from './base.plugin';
import { Finding, Payload, PluginContext } from '../types';
import { FormSurface } from '../surfaces/form.surface';
import { ApiBodySurface } from '../surfaces/api-body.surface';
import { detectAuthBypass } from '../core/auth';
import { QueryParamSurface } from '../surfaces/query-param.surface';

const NOSQL_ERROR_PATTERNS = [
  'mongoerror',
  'mongoparseerror',
  'cast to objectid failed',
  'cannot read property',
  'unexpected token',
  '$where',
  'bsontypecallerror',
  'e11000 duplicate key',
  'bulkwriteerror',
  'document failed validation',
];

// Only match indicators that strongly suggest an auth bypass occurred.
// Avoid generic words (e.g. "account", "welcome") that appear in navbars
// even on non-authenticated pages and cause false positives.
const NOSQL_SUCCESS_INDICATORS = [
  'sign out',
  'log out',
  'cerrar sesion',
  'logged in as',
  'welcome back',
  'your account has been',
];

const REMEDIATION =
  'Sanitize and validate all user input before passing to MongoDB queries. ' +
  'Use ODM libraries like Mongoose with strict schema validation. ' +
  'Disable $where operator and JavaScript execution in MongoDB configuration. ' +
  'Reference: https://owasp.org/www-community/attacks/Testing_for_NoSQL_injection';

export class NoSqlInjectionPlugin extends BasePlugin {
  readonly id = 'nosql-injection' as const;
  readonly name = 'NoSQL Injection';
  readonly description =
    'Tests for NoSQL injection vulnerabilities targeting MongoDB operator injection ($gt, $ne, $where, $regex)';

  loadPayloads(): void {
    this.payloads = require(
      path.join(__dirname, '../patterns/nosql/payloads.json')
    ) as Payload[];
  }

  async run(ctx: PluginContext): Promise<Finding[]> {
    this.loadPayloads();
    const findings: Finding[] = [];

    if (ctx.surfaces.includes('form')) {
      const formSurface = new FormSurface(ctx.page);
      const fields = await formSurface.discoverFields();

      // Capture baseline BEFORE any injection to avoid false positives
      // caused by persistent navbar elements (e.g. "My account").
      const baselineContent = await ctx.page.content();

      for (const field of fields) {
        for (const payload of this.payloads) {
          try {
            const result = await formSurface.inject(field, payload.value);
            const hasError = this.isVulnerableResponse(
              result,
              NOSQL_ERROR_PATTERNS
            );
            const hasAuthBypass = await detectAuthBypass(
              ctx.page,
              baselineContent
            );
            if (hasError || hasAuthBypass) {
              findings.push(
                this.createFinding(
                  ctx,
                  payload,
                  'form',
                  field.name,
                  `NoSQL indicator detected after injecting into "${field.name}": ${payload.value}. ${hasAuthBypass ? 'Auth state changed after injection (bypass suspected).' : 'NoSQL error pattern leaked in response.'}`,
                  REMEDIATION
                )
              );
            }
          } catch {
            // continue
          }
        }
      }
    }

    if (ctx.surfaces.includes('api-body')) {
      const apiSurface = new ApiBodySurface(ctx.page);
      const endpoints = await apiSurface.discoverEndpoints();

      for (const endpoint of endpoints) {
        for (const payload of this.payloads) {
          try {
            const result = await apiSurface.inject(
              endpoint.url,
              endpoint.method,
              endpoint.sampleBody,
              payload.value
            );
            const hasError = this.isVulnerableResponse(
              result,
              NOSQL_ERROR_PATTERNS
            );
            const hasSuccess = this.isVulnerableResponse(
              result,
              NOSQL_SUCCESS_INDICATORS
            );
            if (hasError || hasSuccess) {
              findings.push(
                this.createFinding(
                  ctx,
                  payload,
                  'api-body',
                  endpoint.url,
                  `NoSQL indicator in API response for ${endpoint.method} ${endpoint.url}: ${payload.value}`,
                  REMEDIATION
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
            const result = await qpSurface.inject(
              ctx.target.url,
              param,
              payload.value
            );
            if (this.isVulnerableResponse(result, NOSQL_ERROR_PATTERNS)) {
              findings.push(
                this.createFinding(
                  ctx,
                  payload,
                  'query-param',
                  param,
                  `NoSQL error in response after injecting into query param "${param}": ${payload.value}`,
                  REMEDIATION
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
