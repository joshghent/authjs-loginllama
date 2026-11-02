# authjs-loginllama

Scores every [Auth.js](https://authjs.dev) (NextAuth) sign-in for risk and
refuses the dangerous ones before a session exists.

Auth.js checks the password. It does not ask whether the login looks right. A
correct password from a Tor exit node, a country the user has never been to, or
a bot that has just tried four thousand other accounts still gets a session.
This package asks [LoginLlama](https://loginllama.app) first.

```bash
npm install authjs-loginllama
```

Wrap the `authorize` function of your Credentials provider:

```ts
// auth.ts
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { withLoginLlama } from 'authjs-loginllama';
import { verifyPassword } from './users'; // your own user lookup

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    Credentials({
      credentials: { email: {}, password: {} },
      authorize: withLoginLlama(({ email, password }) =>
        verifyPassword(String(email), String(password))
      )
    })
  ]
});
```

Set `LOGINLLAMA_API_KEY` in your environment. The first 1,000 checks are free:
[get a key](https://loginllama.app/signup).

It works the same with SvelteKit, Express and anything else on `@auth/core`.

## What it does

Your `authorize` runs first. When it accepts the password, the package sends
the email, IP address and user agent to LoginLlama. It gets back a score from 0
to 10 and reason codes such as `known_tor_exit_node`, `known_vpn`,
`impossible_travel_detected`, `new_login_location` and `known_bot`. At 8 or
above the sign-in fails with `RiskySignIn`, and Auth.js sends the user back to
the sign-in page with `?code=risky_sign_in`.

When `authorize` returns `null` the package reports a failed attempt. That is
how LoginLlama spots someone guessing passwords, and how it learns each user's
usual devices and places. Each attempt shows up in the
[dashboard](https://loginllama.app/account/dashboard) with its score and
reasons.

If LoginLlama is down or takes longer than two seconds, the sign-in goes
through. A fraud check should never lock your users out.

## Options

```ts
withLoginLlama(authorize, {
  apiKey: process.env.LOGINLLAMA_API_KEY, // the default
  blockAt: 8, // refuse at this score or above
  identify: (credentials) => String(credentials.email) // the default
});
```

Start at 8 and lower it once you have watched real scores for a week.
LoginLlama marks anything above 5 as risky. If your users sign in with a
username, point `identify` at that field.

## Show the error

```ts
// app/login/page.tsx
const code = searchParams.code;
if (code === 'risky_sign_in') {
  // Tell them why, and offer a password reset or support link.
}
```

## OAuth sign-ins

Only the Credentials provider gives Auth.js code a password to check. OAuth
providers such as GitHub and Google have already authenticated the user
somewhere else, so this package does not cover them.

## Requirements

`@auth/core` 0.40 or newer (NextAuth v5 ships it), Node 22.18 or newer. The
package uses `fetch` and has no other dependencies.

## Links

- [LoginLlama for Auth.js](https://loginllama.app/for-authjs)
- [LoginLlama docs](https://loginllama.app/docs)
- [Free IP reputation checker](https://loginllama.app/tools/ip-reputation-checker)

## Licence

MIT
