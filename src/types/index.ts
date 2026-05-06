export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type SurfaceType = 'form' | 'query-param' | 'header' | 'api-body';

export type PluginId =
  | 'sql-injection'
  | 'nosql-injection'
  | 'xss'
  | 'ssti'
  | 'prototype-pollution';

export interface Target {
  name: string;
  url: string;
  loginUrl?: string;
  username?: string;
  password?: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
  postLoginUrlContains?: string;
  apiHeaders?: Record<string, string>;
  surfaces?: SurfaceType[];
}

export interface Payload {
  value: string;
  description: string;
  cveId: string;
  cveUrl: string;
  severity: Severity;
  dbTarget?: string;
}

export interface Finding {
  pluginId: PluginId;
  pluginName: string;
  severity: Severity;
  surface: SurfaceType;
  field: string;
  url: string;
  payload: string;
  cveId: string;
  cveUrl: string;
  description: string;
  evidence: string;
  remediation: string;
  timestamp: string;
}

export interface ScanResult {
  target: Target;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
  totalTested: number;
  passed: boolean;
}

export interface ScanOptions {
  plugins: PluginId[];
  surfaces: SurfaceType[];
  headed: boolean;
  timeout: number;
  pipeline: boolean;
}

export interface AuthResult {
  success: boolean;
  sessionCookies?: string;
  errorMessage?: string;
}

export interface PluginContext {
  target: Target;
  page: import('playwright').Page;
  surfaces: SurfaceType[];
}
