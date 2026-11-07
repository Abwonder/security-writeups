# I read the whole database: six vulnerabilities in one React, Node and Supabase stack

> **TL;DR:** A production SaaS app on React, Node, Supabase and Cloudflare let me become an admin and read every row of customer data. The chain took under fifteen minutes once I understood the schema. The report logged 29 issues. Six of them combined into full compromise, and every one was a configuration default that nobody had changed.

The stack is the one most startups pick. React on the front, Node in the middle, Supabase for auth and Postgres, Cloudflare at the edge. Each piece is well built on its own. The failure lived in the seams between them, in the assumptions each layer made about the layer below.

The client is not named here. Everything else is as it happened.

## The blueprint was public

Gobuster ran first. A 141,000 word list, pointed at the root, for 42 minutes. It returned almost nothing, because the target is a single page application. Routes like `/admin` and `/dashboard` do not exist as folders on disk. They exist inside the JavaScript bundle.

Feroxbuster with deep JavaScript extraction found the shape of the app in under 30 seconds. It crawls every script, pulls every URL out of the code, and follows them. That pass surfaced 35 JavaScript files that were never linked from the UI, a 71 KB root level script with undocumented logic, and an exposed `/.git/` directory on production.

The git folder is the expensive one. `/.git/config` named the private repository. `/.git/index` listed 636 tracked files. The `.gitignore` named files that were supposed to be secret, including `d2-test-credentials.json` and `.dev.vars`. Reading `js/auth.js` handed me the Supabase anon key.

Worth saying plainly: the anon key is designed to be public. It ships to the browser on every Supabase app. The problem is not the key existing. The problem is that the database trusted it, and the exposed repository told me exactly which tables to point it at.

```
GET /.git/HEAD     -> 200 OK
GET /.git/config   -> remote origin: github.com/<org>/<private-repo>
GET /.git/index    -> 636 tracked paths
```

The fix is two lines at the edge and one step in the pipeline.

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

```yaml
# CI, after the build, before the upload
- run: rm -rf dist/.git
```

Then rotate every secret that ever appeared in a commit. Deleting the file does not remove it from history.

## Authentication with no floor

The Supabase anon key let me skip the frontend entirely and talk to the auth API from a terminal.

I sent a signup request for an address I suspected was already registered.

```
POST /auth/v1/signup
{"email":"victim@example.com","password":"x"}
```

The response was HTTP 422, and it named the account.

```json
{
  "error_code": "user_already_exists",
  "msg": "User already registered",
  "email": "victim@example.com",
  "id": "<uuid>",
  "created_at": "<timestamp>"
}
```

A random address returned a different code and a different body. That difference is an enumeration oracle. Automate it and you have a confirmed list of every customer on the platform, with no password and no login.

Next I hit the login endpoint 30 times in a row with wrong passwords. Every response was HTTP 400. Not one was HTTP 429. No lockout, no CAPTCHA, no WAF challenge. Thirty attempts became a script, and a script becomes credential stuffing against a list I already knew was valid.

The fix needs both halves. Uniform responses remove the oracle. Rate limiting removes the amplification.

```js
import rateLimit from 'express-rate-limit';

const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 5,
  standardHeaders: 'draft-7',
});

app.use('/auth/v1', authLimiter);

app.post('/auth/v1/signup', async (req, res) => {
  // never branch the response on whether the address exists
  res.status(200).json({
    msg: 'If this email is registered, you will receive a confirmation link.',
  });
});
```

## The paywall was a column

The subscription lived in `user_profiles`, next to the display name. Four columns mattered: `pro_status`, `pro_expires_at`, `stripe_customer_id` and `role`. Stripe wrote to them through a webhook. The application read them to decide what to render.

Row level security was on. The policy allowed an authenticated user to update their own row. All of it. There was no column list.

That gap has a name, mass assignment, and it turns a profile update into a write primitive against every field the row contains.

```
PATCH /rest/v1/user_profiles?id=eq.<my-user-id>
Authorization: Bearer <my-jwt>

{
  "pro_status": true,
  "pro_expires_at": "2099-12-31T23:59:59Z",
  "stripe_customer_id": "cus_fake_pentest"
}
```

HTTP 204. I refreshed the app and every premium tool opened. Stripe was never contacted. No payment event existed anywhere in the system.

The fix lives at the column level. Remove write access to the fields that carry money, and leave the display name writable.

```sql
revoke update on public.user_profiles from authenticated;

grant update (display_name, avatar_url)
  on public.user_profiles to authenticated;
```

Entitlement checks then read `pro_status` server side and never accept it from a request body.

## Users could write their own role

If `pro_status` was writable, the `role` column in the same row was writable too. The schema from the git dump confirmed it sat in `user_profiles`.

One request.

```
PATCH /rest/v1/user_profiles?id=eq.<my-user-id>
Authorization: Bearer <my-jwt>

{ "role": "admin" }
```

HTTP 204. I went from a test account to platform administrator at the database layer in under five seconds.

The policy had asked one question: are you logged in? It never asked a second question: is this row yours? Those are different questions, and the gap between them is the whole authorization model.

The durable fix moves the role out of a row the user can reach.

```sql
create table public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'user'
);

alter table public.user_roles enable row level security;

-- users may read their own role, and nothing else
create policy "read own role"
  on public.user_roles for select
  using (user_id = auth.uid());
```

No insert, update or delete policy is created for `authenticated`. Role changes happen through a service role in a server function that checks the actor first.

## The token signed its own claims

This is the finding I would put in front of every backend engineer.

The Node API decided whether you were an admin by reading a field inside the JWT:

```js
// reconstructed from js/admin.js
const isAdmin =
  token.user_metadata?.is_admin === true ||
  token.user_metadata?.role === 'admin';
```

The token was signed correctly. The signature verified. The question nobody asked was who controls `user_metadata`. In Supabase, the authenticated user does. It is the field the client writes when it updates its own profile data.

So I wrote the claim myself.

```
PUT /auth/v1/user
Authorization: Bearer <my-current-token>

{ "data": { "is_admin": true, "role": "admin" } }
```

HTTP 200. Then I refreshed the token, and the server minted a new JWT carrying my forged claim, signed with its own key.

```
POST /auth/v1/token?grant_type=refresh_token
Authorization: Bearer <my-current-token>
```

```
GET /api/admin/users
Authorization: Bearer <new-token-with-forged-claims>
```

HTTP 200, with the user table in the body. From the server's point of view the token was cryptographically perfect. It had no way to know the subject wrote the authorization claim into it.

The fix pins the algorithm and moves the authorization decision out of the token.

```js
import { jwtVerify } from 'jose';

const { payload } = await jwtVerify(token, publicKey, {
  algorithms: ['RS256'],           // never read alg from the token
  issuer: 'https://<project>.supabase.co/auth/v1',
  audience: 'authenticated',
});

const { data: roleRow } = await db
  .from('user_roles')
  .select('role')
  .eq('user_id', payload.sub)
  .single();

const isAdmin = roleRow?.role === 'admin';
```

Claims like `sub`, `iss`, `aud` and `exp` are safe to trust after verification. Anything a user can edit needs treating as input, whatever the field is called.

## Every user in one request

With a valid admin token, the admin API from the git dump became a menu.

```
GET /api/admin/users
Authorization: Bearer <forged-admin-token>
```

The handler returned a paginated JSON body with every registered user: `id`, `full_name`, `email`, `country`, `joined`, `plan`, `pro_expires`.

```
?page=1&perPage=1000
```

The pagination was a speed bump, and `perPage` removed it. The whole table came back.

The admin check lived in the React router. The route handler had no access to the router and no idea it existed. On the server, the endpoint was open to anyone holding a token the backend believed was admin.

A frontend route guard is a user experience decision. It is not an access control.

```js
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { page = 1, perPage = 50 } = req.query;
  const limit = Math.min(Number(perPage), 100);   // cap the cap
  const rows = await db.listUsers({ page: Number(page), limit });
  res.json({ users: rows });
});

async function requireAdmin(req, res, next) {
  const role = await getRoleFromDb(req.user.sub);
  if (role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  next();
}
```

Every admin route gets the middleware. Not the parent router. Not the layout. The handler.

## Follow the money

The next endpoint on the same token was `GET /api/admin/purchases`.

```json
{
  "purchases": [
    { "name": "<redacted>", "email": "<redacted>", "tool": "o1a_audit", "created_at": "<date>" },
    { "name": "<redacted>", "email": "<redacted>", "tool": "cv_review", "created_at": "<date>" }
  ]
}
```

Names and emails are bad on their own. The `tool` field is worse. A purchase of `cv_review` says the person is job hunting. A purchase of `o1a_audit` says they are preparing for something. Neither fact is sensitive in isolation. Together with a name and an email, they write the first line of a spear phishing email that lands.

This is the aggregation problem. Privacy law treats the combination as personal data because the combination is what causes harm.

The purchases table had no policy attached at all, so the anon key could read it too. Default deny is the only sane starting point.

```sql
alter table public.purchases enable row level security;
revoke all on public.purchases from anon, authenticated;

create policy "own purchases"
  on public.purchases for select
  using (user_id = auth.uid());
```

Admin reads go through a server function with its own authorization check and its own audit row.

## The widget listened to anyone

The frontend used `postMessage` so a payment iframe could tell the dashboard that an upgrade had started. The listener in `dashboard-inline.js` looked like this:

```js
window.addEventListener('message', function (event) {
  if (event.data === 'initiate-pro-upgrade') {
    initiateStripeCheckout();
  }
});
```

No origin check. Any page on the internet could load the dashboard in a hidden iframe and send that string.

```html
<iframe src="https://<target>/dashboard" id="dash"></iframe>
<script>
  setTimeout(function () {
    document.getElementById('dash')
      .contentWindow
      .postMessage('initiate-pro-upgrade', '*');
  }, 3000);
</script>
```

A logged in user visits my page. Their browser loads the real dashboard, my script sends the message, and the dashboard opens a Stripe checkout that the user did not ask for. I control the timing and the context.

The same missing check allows forced navigation, state changes, and account actions, depending on which handlers exist. The fix is one comparison.

```js
const ALLOWED = new Set(['https://app.example.com']);

window.addEventListener('message', function (event) {
  if (!ALLOWED.has(event.origin)) return;
  if (event.data?.type !== 'initiate-pro-upgrade') return;
  initiateStripeCheckout();
});
```

Check the origin first, then the shape. Never pass the payload to `innerHTML`, and never trust the sender because the message arrived.

## Logout that changed nothing

I logged in, captured the access token and the refresh token, and called the logout endpoint.

```
POST /auth/v1/logout
Authorization: Bearer <access-token>
```

The frontend cleared storage and redirected to the login screen. Then I replayed the original request with the old access token.

```
GET /rest/v1/user_profiles
Authorization: Bearer <old-access-token>
```

HTTP 200. Expected 401. The session was still alive.

This is how stateless JWTs work. The logout call behaved as designed. The server verifies a signature and an `exp` claim, and it keeps no list of tokens it has issued. Logout invalidates the refresh token, which stops new access tokens. It cannot reach back and kill one that already exists.

While testing the session lifecycle I found a second problem. The payment portal endpoint had no auth middleware in front of it.

```
POST /api/create-portal-session
(no Authorization header)
```

HTTP 500, not 401. A 500 means the handler ran. It reached business logic and failed there, which means the authentication check was missing or ordered after the work. Middleware order is part of the security model.

```js
// short lived access tokens, revocable sessions
const ACCESS_TTL = '15m';

app.use('/api', verifyJwt);            // first, always
app.use('/api', checkSessionNotRevoked);

app.post('/api/create-portal-session', requireUser, handler);

// on logout, revoke the session id, not just the refresh token
await db.from('revoked_sessions').insert({ sid: payload.sid, at: now() });
```

Fifteen minutes of exposure beats sixty days. A revocation table gives you the ability to end a session that the token itself cannot express.

## What the pattern teaches

The report listed 29 findings: 8 critical, 4 high, 6 medium, 7 low. The chain above is six of them, and it took under fifteen minutes once the schema was clear.

Look at what the six have in common. The git folder was a deploy step nobody checked. The signup endpoint returned a different body for a known address. The profile policy had no column list. The role lived in a row the user could write. The backend read authorization from a field the user controls. The admin check lived in the browser.

Every one of those is a trust decision made in the wrong layer. The frontend decided what to show. The database decided what to allow. Nobody checked that those two answers matched.

A scanner would have flagged some of this. It would not have chained it. The path from an exposed git folder to a valid admin token needed a human who understood the data model, and that is the argument for reading code during an assessment instead of only running tools.

The other half of the lesson is detection. Six steps of this chain produced logs, and none of them produced an alert. A sudden update to a `role` column by the account that owns the row is not normal. A single actor reading the full user table in a minute is not normal. A token whose `user_metadata` changed and was refreshed seconds later is not normal.

```sql
select actor_id, count(*) as rows_read
from audit_log
where table_name = 'user_profiles'
  and at > now() - interval '1 minute'
group by actor_id
having count(*) > 500;
```

That query is a sketch of the control that was missing. A pentest is a snapshot in January. By March the app has shipped new endpoints and the report is partly obsolete. What closes the gap is continuous monitoring with rules written against your own schema, and someone on call who knows what the alert means.

That is the work I do now: break the stack, then build the detection that would have caught me.

If you run React, Node and Supabase, start with the policies. If you run anything at all, start with the git folder.

---

*Written by Abioye Oyatoye, DevSecOps and security engineer. The engagement is anonymised and the client has been notified. Published for educational purposes.*
