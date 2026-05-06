import { Page } from 'playwright';
import { AuthResult, Target } from '../types';

const LOGIN_SUCCESS_INDICATORS = [
  'logout',
  'sign out',
  'cerrar sesion',
  'dashboard',
  'welcome',
  'bienvenido',
  'account',
  'mi cuenta',
  'profile',
  'perfil',
  'my account',
];

const LOGIN_FAILURE_INDICATORS = [
  'invalid',
  'incorrect',
  'failed',
  'error',
  'wrong password',
  'no account',
  'not found',
  'access denied',
  'contraseña incorrecta',
  'usuario no encontrado',
];

export async function authenticate(
  page: Page,
  target: Target
): Promise<AuthResult> {
  const loginUrl = target.loginUrl || target.url;

  try {
    await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 15000 });

    const usernameSelector =
      target.usernameSelector ||
      (await detectUsernameField(page));

    const passwordSelector =
      target.passwordSelector ||
      (await detectPasswordField(page));

    const submitSelector =
      target.submitSelector ||
      (await detectSubmitButton(page));

    if (!usernameSelector || !passwordSelector) {
      return {
        success: false,
        errorMessage: 'Could not locate login form fields on the page.',
      };
    }

    await page.fill(usernameSelector, target.username || '');
    await page.fill(passwordSelector, target.password || '');

    if (submitSelector) {
      await page.click(submitSelector);
    } else {
      await page.keyboard.press('Enter');
    }

    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});

    const content = (await page.content()).toLowerCase();
    const currentUrl = page.url();

    const hasSuccess = LOGIN_SUCCESS_INDICATORS.some((indicator) =>
      content.includes(indicator)
    );
    const hasFailure = LOGIN_FAILURE_INDICATORS.some((indicator) =>
      content.includes(indicator)
    );
    const urlChanged = currentUrl !== loginUrl;

    if (hasSuccess || (urlChanged && !hasFailure)) {
      return { success: true };
    }

    if (hasFailure) {
      return {
        success: false,
        errorMessage:
          'Login failed: page contains failure indicators. Check credentials in .env.',
      };
    }

    return {
      success: false,
      errorMessage:
        'Login result is inconclusive. The page did not show clear success or failure.',
    };
  } catch (err: unknown) {
    return {
      success: false,
      errorMessage: `Authentication error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export async function validateSession(page: Page): Promise<boolean> {
  const content = (await page.content()).toLowerCase();
  return LOGIN_SUCCESS_INDICATORS.some((i) => content.includes(i));
}

async function detectUsernameField(page: Page): Promise<string | null> {
  const selectors = [
    'input[type="email"]',
    'input[name="email"]',
    'input[name="username"]',
    'input[name="user"]',
    'input[name="login"]',
    'input[id*="email"]',
    'input[id*="user"]',
    'input[placeholder*="email" i]',
    'input[placeholder*="usuario" i]',
    'input[placeholder*="correo" i]',
    'input[type="text"]:first-of-type',
  ];

  for (const sel of selectors) {
    const el = await page.$(sel);
    if (el) return sel;
  }
  return null;
}

async function detectPasswordField(page: Page): Promise<string | null> {
  const selectors = [
    'input[type="password"]',
    'input[name="password"]',
    'input[name="pass"]',
    'input[name="pwd"]',
    'input[id*="password"]',
    'input[id*="pass"]',
  ];

  for (const sel of selectors) {
    const el = await page.$(sel);
    if (el) return sel;
  }
  return null;
}

async function detectSubmitButton(page: Page): Promise<string | null> {
  const selectors = [
    'button[type="submit"]',
    'input[type="submit"]',
    'button:has-text("Login")',
    'button:has-text("Sign In")',
    'button:has-text("Iniciar")',
    'button:has-text("Entrar")',
    'button:has-text("Log In")',
    '[class*="login"]',
    '[id*="submit"]',
  ];

  for (const sel of selectors) {
    const el = await page.$(sel);
    if (el) return sel;
  }
  return null;
}
