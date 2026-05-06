import { Page } from 'playwright';
import { AuthResult, Target } from '../types';

const LOGIN_SUCCESS_INDICATORS = [
  'logout',
  'sign out',
  'cerrar sesion',
  'log out',
  'logged in as',
  'welcome back',
  'bienvenido de nuevo',
];

const LOGIN_FAILURE_INDICATORS = [
  'invalid',
  'incorrect',
  'failed',
  'wrong password',
  'no account',
  'not found',
  'access denied',
  'contraseña incorrecta',
  'usuario no encontrado',
  'credenciales incorrectas',
  'unauthorized',
];

export async function authenticate(
  page: Page,
  target: Target
): Promise<AuthResult> {
  const loginUrl = target.loginUrl || target.url;

  try {
    await page.goto(loginUrl, { waitUntil: 'networkidle', timeout: 15000 });

    const usernameSelector =
      target.usernameSelector || (await detectUsernameField(page));

    const passwordSelector =
      target.passwordSelector || (await detectPasswordField(page));

    const submitSelector =
      target.submitSelector || (await detectSubmitButton(page));

    if (!usernameSelector || !passwordSelector) {
      return {
        success: false,
        errorMessage:
          'Could not locate login form fields. Define TARGET_USERNAME_SELECTOR and TARGET_PASSWORD_SELECTOR in .env for this app.',
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

    return evaluateAuthResult(page, target, loginUrl);
  } catch (err: unknown) {
    return {
      success: false,
      errorMessage: `Authentication error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function evaluateAuthResult(
  page: Page,
  target: Target,
  loginUrl: string
): AuthResult {
  const currentUrl = page.url();

  // Strategy 1 (most reliable): URL contains the expected post-login path
  if (target.postLoginUrlContains) {
    if (currentUrl.includes(target.postLoginUrlContains)) {
      return { success: true };
    }
    return {
      success: false,
      errorMessage: `Login failed: expected URL to contain "${target.postLoginUrlContains}" after login but landed on "${currentUrl}".`,
    };
  }

  // Strategy 2: URL changed away from login page (redirect = login succeeded)
  const urlChanged = currentUrl !== loginUrl && !currentUrl.includes('login');
  if (urlChanged) {
    return { success: true };
  }

  // Strategy 3: look for text-based indicators in page content
  // (sync wrapper — caller must await page.content() before calling this if needed)
  return {
    success: false,
    errorMessage:
      'Login result is inconclusive. Consider setting TARGET_POST_LOGIN_URL_CONTAINS in .env for this app.',
  };
}

export async function validateSession(page: Page, target: Target): Promise<boolean> {
  const currentUrl = page.url();

  if (target.postLoginUrlContains) {
    return currentUrl.includes(target.postLoginUrlContains);
  }

  const content = (await page.content()).toLowerCase();
  return LOGIN_SUCCESS_INDICATORS.some((i) => content.includes(i));
}

// Detects auth bypass by comparing URL and content BEFORE vs AFTER injection.
// Avoids false positives from persistent navbar elements like "My account".
export async function detectAuthBypass(
  page: Page,
  baselineContent: string,
  baselineUrl: string,
  target: Target
): Promise<boolean> {
  const currentUrl = page.url();

  // URL-based: most reliable signal — app redirected to a protected area
  if (target.postLoginUrlContains) {
    return (
      currentUrl.includes(target.postLoginUrlContains) &&
      !baselineUrl.includes(target.postLoginUrlContains)
    );
  }

  // Content-based: only flag if indicators appear NOW but were NOT in baseline
  const current = (await page.content()).toLowerCase();
  const baseline = baselineContent.toLowerCase();
  return (
    LOGIN_SUCCESS_INDICATORS.some((i) => current.includes(i)) &&
    !LOGIN_SUCCESS_INDICATORS.some((i) => baseline.includes(i))
  );
}

async function detectUsernameField(page: Page): Promise<string | null> {
  const selectors = [
    'input[type="email"]',
    'input[name="email"]',
    'input[name="username"]',
    'input[name="user"]',
    'input[name="login"]',
    'input[name="usuario"]',
    'input[id*="email"]',
    'input[id*="user"]',
    'input[id*="login"]',
    'input[placeholder*="email" i]',
    'input[placeholder*="usuario" i]',
    'input[placeholder*="correo" i]',
    'input[placeholder*="user" i]',
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
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
    'input[name="contrasena"]',
    'input[name="clave"]',
    'input[id*="password"]',
    'input[id*="pass"]',
    'input[autocomplete="current-password"]',
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
    'button:has-text("Log In")',
    'button:has-text("Iniciar sesión")',
    'button:has-text("Iniciar")',
    'button:has-text("Entrar")',
    'button:has-text("Ingresar")',
    'button:has-text("Acceder")',
    'button:has-text("Continue")',
    '[class*="login-btn"]',
    '[id*="login-btn"]',
    '[id*="btn-login"]',
    '[data-testid*="login"]',
    '[data-testid*="submit"]',
  ];

  for (const sel of selectors) {
    const el = await page.$(sel);
    if (el) return sel;
  }
  return null;
}
