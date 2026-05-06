import { Page } from 'playwright';

export async function takeScreenshot(page: Page): Promise<string> {
  try {
    const buffer = await page.screenshot({ type: 'png', fullPage: false });
    return buffer.toString('base64');
  } catch {
    return '';
  }
}
