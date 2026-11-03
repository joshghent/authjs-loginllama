import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { Auth } from '@auth/core';
import Credentials from '@auth/core/providers/credentials';
import { withLoginLlama } from './index.ts';

// Stands in for the LoginLlama API: answers with `score`, records each call.
let score: number | 'down' = 0;
let calls: {
  identity_key: string;
  authentication_outcome: string;
  ip_address?: string;
}[] = [];
const realFetch = globalThis.fetch;
let source: string | null = null;
globalThis.fetch = async (input, init) => {
  if (String(input).startsWith('https://loginllama.app/')) {
    source = new Headers(init?.headers).get('x-loginllama-source');
    if (score === 'down') throw new TypeError('fetch failed');
    calls.push(JSON.parse(String(init?.body)));
    return Response.json({
      data: { attributes: { risk_score: score, risk_codes: [] } }
    });
  }
  return realFetch(input, init);
};

const PASSWORD = 'correct-horse-battery';
const config = {
  secret: 'test-secret-that-is-long-enough-for-auth-js',
  trustHost: true,
  basePath: '/auth',
  providers: [
    Credentials({
      credentials: { email: {}, password: {} },
      authorize: withLoginLlama(
        ({ email, password }) =>
          password === PASSWORD ? { id: '1', email: String(email) } : null,
        { apiKey: 'test-key' }
      )
    })
  ]
};

// Through the HTTP handler, so each test sees what a browser would: fetch a
// CSRF token, then post the form.
async function signIn(password = PASSWORD) {
  const csrf = await Auth(new Request('http://localhost/auth/csrf'), config);
  const { csrfToken } = await csrf.json();
  const cookie = csrf.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .join('; ');

  const response = await Auth(
    new Request('http://localhost/auth/callback/credentials', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'x-forwarded-for': '203.0.113.7, 10.0.0.1',
        'user-agent': 'Mozilla/5.0 (test)',
        cookie
      },
      body: new URLSearchParams({
        csrfToken,
        email: 'ada@example.test',
        password
      })
    }),
    config
  );
  const location = response.headers.get('location') ?? '';
  const sessionSet = response.headers
    .getSetCookie()
    .some((c) => c.startsWith('authjs.session-token='));
  return { location, sessionSet };
}

beforeEach(() => {
  score = 0;
  calls = [];
});

test('lets a low-risk sign-in through and reports success', async () => {
  const { sessionSet } = await signIn();
  assert.equal(sessionSet, true);
  assert.deepEqual(calls, [
    {
      identity_key: 'ada@example.test',
      ip_address: '203.0.113.7',
      user_agent: 'Mozilla/5.0 (test)',
      authentication_outcome: 'success'
    }
  ]);
});

test('refuses a sign-in at the block threshold', async () => {
  score = 8;
  const { sessionSet, location } = await signIn();
  assert.equal(sessionSet, false);
  assert.match(location, /code=risky_sign_in/);
});

test('reports a wrong password as failed', async () => {
  const { sessionSet } = await signIn('wrong-password');
  assert.equal(sessionSet, false);
  assert.equal(calls[0].authentication_outcome, 'failed');
});

test('fails open when LoginLlama is unreachable', async () => {
  score = 'down';
  const { sessionSet } = await signIn();
  assert.equal(sessionSet, true);
});

test('refuses to start without an API key', () => {
  const saved = process.env.LOGINLLAMA_API_KEY;
  delete process.env.LOGINLLAMA_API_KEY;
  try {
    assert.throws(() => withLoginLlama(() => null), /LOGINLLAMA_API_KEY/);
  } finally {
    if (saved) process.env.LOGINLLAMA_API_KEY = saved;
  }
});

test('tells LoginLlama which integration sent the check', async () => {
  await signIn();
  assert.equal(source, 'authjs-loginllama');
});
