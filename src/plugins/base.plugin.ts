import { Finding, Payload, PluginContext, PluginId, SurfaceType } from '../types';

export abstract class BasePlugin {
  abstract readonly id: PluginId;
  abstract readonly name: string;
  abstract readonly description: string;

  protected payloads: Payload[] = [];

  abstract loadPayloads(): void;
  abstract run(ctx: PluginContext): Promise<Finding[]>;

  protected createFinding(
    ctx: PluginContext,
    payload: Payload,
    surface: SurfaceType,
    field: string,
    evidence: string,
    remediation: string
  ): Finding {
    return {
      pluginId: this.id,
      pluginName: this.name,
      severity: payload.severity,
      surface,
      field,
      url: ctx.target.url,
      payload: payload.value,
      cveId: payload.cveId,
      cveUrl: payload.cveUrl,
      description: payload.description,
      evidence,
      remediation,
      timestamp: new Date().toISOString(),
    };
  }

  protected isVulnerableResponse(
    content: string,
    errorPatterns: string[]
  ): boolean {
    const lower = content.toLowerCase();
    return errorPatterns.some((p) => lower.includes(p.toLowerCase()));
  }
}
