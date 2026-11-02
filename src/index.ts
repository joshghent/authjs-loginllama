import { CredentialsSignin } from '@auth/core/errors';
import type { User } from '@auth/core/types';

export type LoginLlamaOptions = {
  /** Defaults to `process.env.LOGINLLAMA_API_KEY`. */
  apiKey?: string;
  /**
   * Refuse the sign-in at this score or above (0 to 10). LoginLlama calls
   * anything over 5 risky; 8 refuses only the clearest cases while you watch
   * real scores in the dashboard.
   */
  blockAt?: number;
  /**
   * Which credential names the person. Defaults to the `email` field, which is
   * also where LoginLlama sends new-login alerts.
   */
  identify?: (credentials: Partial<Record<string, unknown>>) => string;
};

type Authorize = (
  credentials: Partial<Record<string, unknown>>,
  request: Request
) => Promise<User | null> | User | null;

type Outcome = 'success' | 'failed';
type LoginCheck = { risk_score: number; risk_codes: string[] };

const CHECK_URL = 'https://loginllama.app/api/v1/login/check';

/** Thrown for a risky sign-in. Auth.js puts `code` in the redirect URL. */
export class RiskySignIn extends CredentialsSignin {
  code = 'risky_sign_in';
}

/**
 * Wraps a Credentials provider's `authorize`. Once your code has accepted the
 * password, LoginLlama scores the sign-in, and at `blockAt` or above the
 * sign-in fails with `RiskySignIn` before a session exists. A wrong password
 * is reported too, so LoginLlama can spot someone guessing.
 */
export const withLoginLlama = (
  authorize: Authorize,
  {
    apiKey = process.env.LOGINLLAMA_API_KEY,
    blockAt = 8,
    identify = (credentials) => String(credentials.email ?? '')
  }: LoginLlamaOptions = {}
): Authorize => {
  if (!apiKey) {
    throw new Error(
      'authjs-loginllama: set LOGINLLAMA_API_KEY or pass { apiKey }. Get a free key at https://loginllama.app/signup'
    );
  }

  // Fails open: an outage, on our side or yours, must never lock people out.
  async function check(
    identity: string,
    request: Request,
    outcome: Outcome
  ): Promise<LoginCheck | null> {
    const response = await fetch(CHECK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/vnd.api+json',
        'X-API-KEY': apiKey!
      },
      body: JSON.stringify({
        identity_key: identity,
        ip_address: request.headers
          .get('x-forwarded-for')
          ?.split(',')[0]
          ?.trim(),
        user_agent: request.headers.get('user-agent') ?? undefined,
        authentication_outcome: outcome
      }),
      signal: AbortSignal.timeout(2000)
    }).catch(() => null);

    if (!response?.ok) return null;
    return (await response.json()).data.attributes;
  }

  return async (credentials, request) => {
    const identity = identify(credentials);
    const user = await authorize(credentials, request);
    if (!identity) return user;

    const result = await check(identity, request, user ? 'success' : 'failed');
    if (user && result && result.risk_score >= blockAt) throw new RiskySignIn();
    return user;
  };
};
