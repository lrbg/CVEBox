import dotenv from 'dotenv';
import path from 'path';
import { Target } from '../types';

dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export function loadTargets(): Target[] {
  const targets: Target[] = [];
  let index = 1;

  while (true) {
    const suffix = index === 1 ? '' : `_${index}`;
    const url = process.env[`TARGET${suffix}_URL`] || process.env[`TARGET_URL${suffix}`];
    if (!url) break;

    targets.push({
      name: process.env[`TARGET${suffix}_NAME`] || process.env[`TARGET_NAME${suffix}`] || `App-${index}`,
      url,
      loginUrl: process.env[`TARGET${suffix}_LOGIN_URL`] || process.env[`TARGET_LOGIN_URL${suffix}`] || url,
      username: process.env[`TARGET${suffix}_USERNAME`] || process.env[`TARGET_USERNAME${suffix}`],
      password: process.env[`TARGET${suffix}_PASSWORD`] || process.env[`TARGET_PASSWORD${suffix}`],
      usernameSelector: process.env[`TARGET${suffix}_USERNAME_SELECTOR`],
      passwordSelector: process.env[`TARGET${suffix}_PASSWORD_SELECTOR`],
      submitSelector: process.env[`TARGET${suffix}_SUBMIT_SELECTOR`],
      apiHeaders: parseHeaders(process.env[`TARGET${suffix}_API_HEADERS`]),
    });

    index++;
  }

  if (targets.length === 0) {
    throw new Error(
      'No targets found in .env file. Define at least TARGET_URL, TARGET_USERNAME, TARGET_PASSWORD.'
    );
  }

  return targets;
}

export function isBrowserHeaded(): boolean {
  return process.env.BROWSER_HEADED === 'true';
}

export function getScanTimeout(): number {
  return parseInt(process.env.SCAN_TIMEOUT_MS || '8000', 10);
}

export function getReportsDir(): string {
  return process.env.REPORTS_DIR || path.resolve(process.cwd(), 'reports');
}

function parseHeaders(raw: string | undefined): Record<string, string> | undefined {
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}
