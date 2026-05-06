import { Page } from 'playwright';

export interface FormField {
  name: string;
  selector: string;
  type: string;
}

export class FormSurface {
  constructor(private readonly page: Page) {}

  async discoverFields(): Promise<FormField[]> {
    return this.page.evaluate(() => {
      const fields: { name: string; selector: string; type: string }[] = [];
      const inputs = document.querySelectorAll(
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"]):not([type="file"]), textarea'
      );
      inputs.forEach((el) => {
        const input = el as HTMLInputElement | HTMLTextAreaElement;
        const name = input.name || input.id || input.placeholder || 'unknown';
        const type = (input as HTMLInputElement).type || 'textarea';
        const id = input.id ? `#${input.id}` : '';
        const nameAttr = input.name ? `[name="${input.name}"]` : '';
        const selector = id || nameAttr || input.tagName.toLowerCase();
        fields.push({ name, selector, type });
      });
      return fields;
    });
  }

  async inject(field: FormField, payload: string): Promise<string> {
    try {
      await this.page.fill(field.selector, '');
      await this.page.fill(field.selector, payload);

      const form = await this.page.$(
        `${field.selector} ~ [type="submit"], form:has(${field.selector}) [type="submit"]`
      );
      if (form) {
        await form.click();
      } else {
        await this.page.keyboard.press('Enter');
      }

      await this.page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
      return await this.page.content();
    } catch {
      return await this.page.content();
    }
  }
}
