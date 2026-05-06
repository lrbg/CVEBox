import { Page } from 'playwright';

export class HeaderSurface {
  constructor(private readonly page: Page) {}

  async inject(url: string, headerName: string, payload: string): Promise<string> {
    try {
      await this.page.setExtraHTTPHeaders({ [headerName]: payload });
      await this.page.goto(url, { timeout: 8000 });
      await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      const content = await this.page.content();
      await this.page.setExtraHTTPHeaders({});
      return content;
    } catch {
      await this.page.setExtraHTTPHeaders({}).catch(() => {});
      return await this.page.content().catch(() => '');
    }
  }

  async injectMultiple(
    url: string,
    headers: Record<string, string>
  ): Promise<string> {
    try {
      await this.page.setExtraHTTPHeaders(headers);
      await this.page.goto(url, { timeout: 8000 });
      await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      const content = await this.page.content();
      await this.page.setExtraHTTPHeaders({});
      return content;
    } catch {
      await this.page.setExtraHTTPHeaders({}).catch(() => {});
      return await this.page.content().catch(() => '');
    }
  }
}
