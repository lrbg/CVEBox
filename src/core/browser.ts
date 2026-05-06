import { Browser, BrowserContext, Page, chromium } from 'playwright';

export interface BrowserOptions {
  headed: boolean;
  timeout: number;
}

export class BrowserManager {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;

  async launch(options: BrowserOptions): Promise<void> {
    this.browser = await chromium.launch({
      headless: !options.headed,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
      ],
    });

    this.context = await this.browser.newContext({
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
      },
    });

    this.context.setDefaultTimeout(options.timeout);
  }

  async newPage(): Promise<Page> {
    if (!this.context) throw new Error('Browser not launched. Call launch() first.');
    const page = await this.context.newPage();

    page.on('dialog', async (dialog) => {
      await dialog.dismiss();
    });

    return page;
  }

  async close(): Promise<void> {
    if (this.context) await this.context.close();
    if (this.browser) await this.browser.close();
    this.context = null;
    this.browser = null;
  }
}
