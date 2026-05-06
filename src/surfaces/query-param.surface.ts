import { Page } from 'playwright';

export class QueryParamSurface {
  constructor(private readonly page: Page) {}

  discoverParams(url: string): string[] {
    try {
      const parsed = new URL(url);
      return Array.from(parsed.searchParams.keys());
    } catch {
      return [];
    }
  }

  async inject(baseUrl: string, param: string, payload: string): Promise<string> {
    try {
      const parsed = new URL(baseUrl);
      parsed.searchParams.set(param, payload);
      await this.page.goto(parsed.toString(), { timeout: 8000 });
      await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      return await this.page.content();
    } catch {
      return await this.page.content().catch(() => '');
    }
  }

  async injectRaw(baseUrl: string, rawQueryString: string): Promise<string> {
    try {
      const separator = baseUrl.includes('?') ? '&' : '?';
      const targetUrl = `${baseUrl}${separator}${rawQueryString}`;
      await this.page.goto(targetUrl, { timeout: 8000 });
      await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      return await this.page.content();
    } catch {
      return await this.page.content().catch(() => '');
    }
  }
}
