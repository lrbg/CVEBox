import path from 'path';
import { BasePlugin } from './base.plugin';
import { Finding, Payload, PluginContext } from '../types';
import { FormSurface } from '../surfaces/form.surface';
import { QueryParamSurface } from '../surfaces/query-param.surface';
import { ApiBodySurface } from '../surfaces/api-body.surface';
import { takeScreenshot } from '../core/screenshot';

const SQL_ERROR_PATTERNS = [
  'sql syntax',
  'mysql_fetch',
  'ora-',
  'pg_query',
  'sqlite_',
  'unclosed quotation',
  'syntax error',
  'odbc driver',
  'sqlstate',
  'microsoft ole db',
  'invalid query',
  'sql server',
  'division by zero',
  'unterminated string',
  'quoted string not properly terminated',
  'you have an error in your sql',
];

const REMEDIATION =
  'Use parameterized queries / prepared statements. Never concatenate user input directly into SQL strings. ' +
  'Apply input validation and least-privilege database accounts. ' +
  'Reference: https://owasp.org/www-community/attacks/SQL_Injection';

export class SqlInjectionPlugin extends BasePlugin {
  readonly id = 'sql-injection' as const;
  readonly name = 'SQL Injection';
  readonly description =
    'Tests for SQL injection vulnerabilities across MySQL, PostgreSQL, SQL Server, Oracle and generic databases';

  loadPayloads(): void {
    this.payloads = require(
      path.join(__dirname, '../patterns/sql/payloads.json')
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
            if (this.isVulnerableResponse(result, SQL_ERROR_PATTERNS)) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'form', field.name,
                  `SQL error detected in response after injecting payload into field "${field.name}": ${payload.value}`,
                  REMEDIATION, screenshotBefore, screenshotAfter
                )
              );
            }
          } catch {
            // continue on individual field errors
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
            if (this.isVulnerableResponse(result, SQL_ERROR_PATTERNS)) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'query-param', param,
                  `SQL error in response after injecting payload into query param "${param}": ${payload.value}`,
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

    if (ctx.surfaces.includes('api-body')) {
      const apiSurface = new ApiBodySurface(ctx.page);
      const endpoints = await apiSurface.discoverEndpoints();

      for (const endpoint of endpoints) {
        for (const payload of this.payloads) {
          try {
            const screenshotBefore = await takeScreenshot(ctx.page);
            const result = await apiSurface.inject(endpoint.url, endpoint.method, endpoint.sampleBody, payload.value);
            if (this.isVulnerableResponse(result, SQL_ERROR_PATTERNS)) {
              const screenshotAfter = await takeScreenshot(ctx.page);
              findings.push(
                this.createFinding(
                  ctx, payload, 'api-body', endpoint.url,
                  `SQL error in API response after injecting payload into ${endpoint.method} ${endpoint.url}: ${payload.value}`,
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
