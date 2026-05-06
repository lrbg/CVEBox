import { Page } from 'playwright';

export interface ApiEndpoint {
  url: string;
  method: string;
  sampleBody: Record<string, unknown>;
}

export class ApiBodySurface {
  constructor(private readonly page: Page) {}

  async discoverEndpoints(): Promise<ApiEndpoint[]> {
    const endpoints: ApiEndpoint[] = [];
    const requests: ApiEndpoint[] = [];

    this.page.on('request', (req) => {
      const method = req.method();
      if (['POST', 'PUT', 'PATCH'].includes(method)) {
        try {
          const body = req.postDataJSON() as Record<string, unknown> | null;
          if (body) {
            requests.push({ url: req.url(), method, sampleBody: body });
          }
        } catch {
          // not JSON body
        }
      }
    });

    await this.page.waitForTimeout(1000);

    const seen = new Set<string>();
    for (const r of requests) {
      const key = `${r.method}:${r.url}`;
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push(r);
      }
    }

    return endpoints;
  }

  async inject(
    url: string,
    method: string,
    sampleBody: Record<string, unknown>,
    payload: string
  ): Promise<string> {
    try {
      const injectedBody = this.injectIntoObject(sampleBody, payload);
      const response = await this.page.evaluate(
        async ({ url, method, body }) => {
          const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          return res.text();
        },
        { url, method, body: injectedBody }
      );
      return response as string;
    } catch {
      return '';
    }
  }

  async injectRaw(url: string, method: string, rawBody: string): Promise<string> {
    try {
      const response = await this.page.evaluate(
        async ({ url, method, body }) => {
          const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body,
          });
          return res.text();
        },
        { url, method, body: rawBody }
      );
      return response as string;
    } catch {
      return '';
    }
  }

  private injectIntoObject(
    obj: Record<string, unknown>,
    payload: string
  ): Record<string, unknown> {
    const injected: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
      if (typeof val === 'string') {
        injected[key] = payload;
      } else if (typeof val === 'object' && val !== null) {
        injected[key] = this.injectIntoObject(
          val as Record<string, unknown>,
          payload
        );
      } else {
        injected[key] = val;
      }
    }
    return injected;
  }
}
