# Security Policy

This project is a **single sign-on provider for ISPConfig**: it mints short-lived, single-use tokens
that log a browser into a hosting control panel. A token is a password substitute. That makes this
repository security-sensitive in a way most panel extensions are not, and it is why this policy is
specific rather than boilerplate.

Two things are in scope, and they are one contract:

- `interface/web/connectsso/lib/classes/remote.d/connectsso.inc.php` — the **mint** half, reachable
  over ISPConfig's remote API by any caller holding a granted remote-user session;
- `interface/web/connectsso/index.php` — the **redeem** half, an authentication endpoint reachable
  **without a session** by anyone who can reach the panel.

## Reporting a vulnerability

Report privately to **security@noiz.co.za**. Do not open a public issue or pull request for anything
that could be used against a live panel.

Please include:

- what an attacker gains, stated plainly;
- the exact request or call sequence that demonstrates it;
- the ISPConfig version and patch level, and the release or commit of this project;
- whether the panel is behind a reverse proxy, and the value of `reverse_proxy_panel_allowed`.

**Never include a live token.** If a token is still inside its 45-second window it is a working
login. A SHA-256 of one is fine, and so is a redacted one.

You will get an acknowledgement, and then either a fix or an assessment explaining why the behaviour
is intended. Coordinated disclosure is welcome and credit is offered by default — say if you would
rather not be named.

If a report turns out to be an ISPConfig **core** issue rather than one in this repository, it is
redirected upstream to the ISPConfig project with credit.

## Supported versions

The latest tagged release receives fixes.

Developed and verified against **ISPConfig 3.3.1p1**, which is the only version any claim in this
repository has been checked against. Earlier 3.x releases are untested — neither claimed nor
supported. Re-verify after a major ISPConfig upgrade: nothing this project depends on is upstream
API, and the line-number citations throughout the source are version-specific.

## The trust boundary

**Minting** requires all of:

1. the remote API to be enabled (`remote_api_allowed = yes` in `security_settings.ini`);
2. a valid ISPConfig **remote user** session — client-login sessions are refused outright, and the
   check fails closed on a session that cannot prove `client_login = 0`;
3. the `connect_sso_token_create` grant on that remote user;
4. a TLS request, or a panel whose operator declared a reverse proxy in `security_settings.ini`.

**Redeeming** requires possession of an unexpired, unredeemed token, from the bound address if one
was set, over TLS, on a panel not in maintenance mode, for an account that is still active, still not
locked, and still not an administrator.

**Anyone holding the grant can mint a login for every non-administrator account on the panel,
including resellers.** ISPConfig gives resellers no distinct user type, so a reseller's token opens a
session that administers that reseller's sub-clients. That is the intended feature set, and it is the
reason the grant should go to exactly one API user with a populated Remote Access IP list. Treat a
leaked API credential holding this grant as a full panel compromise below the admin line.

Administrator accounts are refused at mint **and** again at redemption. The second check is not
redundant: it means a row inserted into `connectsso_token` by some other means still cannot become an
admin login.

## What to attack

Findings in these areas are what this policy exists for:

- any way to obtain a valid token without the grant, or for an account the caller should not reach —
  especially anything that gets a **client-login** session past the mint gate, which would be
  cross-tenant panel takeover;
- any way to redeem a token twice, after expiry, or from an address it was bound away from;
- any way to reach an **administrator** session through either half;
- any way to make the redemption endpoint an oracle — anything that lets a visitor tell "expired"
  from "replayed" from "unknown" from the response;
- session fixation or session confusion around the panel session it builds;
- any way past the 2FA or forced-password-change hand-off;
- an open redirect out of `index.php`, or any request input reaching the `Location:` header;
- SQL injection, or a statement that core's `securityScan()` silently rejects (which fails closed but
  breaks the control it belongs to);
- a token, a token hash, or a panel password reaching any log, response body or stored column;
- anything in `install.sh` / `uninstall.sh` / `bin/` that a non-root user can influence, or that
  leaves a panel half-installed in an exploitable state.

## Known and accepted — please do not report these as new

Each of these is documented in the README, deliberate, and not a finding on its own. A concrete
*escalation* of one of them is very much a finding.

- **The token appears in the panel's access log** when the browser arrives by redirect. A GET carries
  it in the URL. This is inherent to one-time-login links (cPanel and Plesk have the same property)
  and is why tokens are single-use, sub-minute and stored hashed. The endpoint also accepts the token
  by POST so a caller can avoid it entirely.
- **Login CSRF.** Someone who can make a victim's browser open *their* token lands that victim in
  *their* account. Not fully preventable in a redirect-based flow; IP binding blocks it where the
  topology allows.
- **The TLS gate checks the connection PHP sees**, not end-to-end encryption. Where the operator
  declared a reverse proxy it steps aside entirely, and TLS termination becomes the proxy's problem.
  It says nothing about the calling system's own certificate verification, which is that system's
  responsibility.
- **`REMOTE_ADDR` only.** `X-Forwarded-For` and friends are client-supplied and are never consulted,
  for the rate limiter or for IP binding. Behind a proxy that does not rewrite `REMOTE_ADDR`, the
  rate limiter buckets every visitor together — that is the documented trade-off, chosen over
  trusting a spoofable header on an authentication path.
- **`md5()` on the rate-limit bucket key.** It matches ISPConfig's own `attempts_login` convention.
  It is a bucket key and a small PII-hygiene measure, not a secrecy control — the IPv4 space is
  enumerable under any hash — so md5's weakness is irrelevant here.
- **Refusals after the token was already burned do not count against the rate limit** (maintenance
  mode, a vanished user, a client suspended in the interim). Reaching them costs a genuine, spent
  token, so they are useless for guessing, and counting them would let one maintenance window
  exhaust the shared budget of every visitor behind one address. All of them are still audited.
- **The redeemed panel session has the panel's own lifetime.** The 45 seconds bounds the hand-off,
  not the session that follows.
- **The grant checkbox can be ticked for any remote user by an administrator.** There is no way for
  this project to prevent an admin from granting something to the wrong API user; the README says
  what that grant is worth.

## No core file is modified, and this is the whole write surface

Nothing here patches, replaces or edits any ISPConfig core file. The module attaches through core's
own `remote.d` auto-loader — dropping the directory in registers the function, deleting it
unregisters it — so an ISPConfig upgrade cannot overwrite a change that was never made.

| What | When | Written by |
|---|---|---|
| `connectsso_token` — the module's own table | mint, redeem, garbage collection | the mint function, the redemption endpoint |
| `connectsso_attempt` — the module's own table | a failed redemption, a successful one (clears it), garbage collection | the redemption endpoint |
| `sys_user.modules` — adding or removing the string `connectsso`, on `typ = 'admin'` rows only | install / uninstall | `bin/connectsso_module.php` |
| `sys_log`, `/var/log/ispconfig/auth.log` | every mint, refusal and sign-in | both halves |

That is the complete list. There are no other schema changes and no `ALTER` against any core table.
The only ISPConfig-owned state written is the two rows in that table: `sys_user.modules`, once, at
install and uninstall time; and the audit trail, appended at runtime through core's own logging API
exactly as a core remote function's log lines are. Nothing else ISPConfig owns is written. Both module tables are dropped on uninstall by default,
and losing them costs nothing — everything in them expires within a minute (tokens) or five
(rate-limit buckets).

## The pre-auth surface

`interface/web/connectsso/index.php` runs for anyone who can reach the panel, with no session. It is
written for that:

- **TLS is checked before the token is read**, before the rate limiter, before anything.
- **The rate limiter runs before the token is read**, so a guessing loop is bounded regardless of
  which check would have rejected the value.
- **Every token-related refusal renders the identical 403 page.** The real reason goes to the audit
  log only. The two refusals carrying a different status (429 rate limit, 503 maintenance) are
  properties of the server, not of the token.
- **The redirect target is a fixed `/index.php`.** No request input reaches it.
- **The clear token is dropped from memory and from the superglobals** as soon as it has been hashed,
  so it cannot resurface in a later dump, trace or template variable.
- **`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
  `X-Robots-Tag: noindex`** on every response.

The `.php` files under `interface/web/connectsso/lib/` also sit inside the panel's document root, and
neither stock vhost template denies a `.php` under `lib/` (the Apache one denies only `*.lng`, the
nginx one `*.lng` plus dotfiles). Each therefore carries its own direct-request guard: requested over
HTTP without the panel bootstrap, it answers 404 and stops — no fatal, no path disclosure. An
`.htaccess` would not be reliable there (`AllowOverride None` in the mpm_itk vhost; nginx ignores it
entirely), which is why the guard lives in the files.

## The consuming system's authorisation is outside this boundary

Worth stating on its own, because in practice it is the likeliest way a panel running this project
gets breached — and no report against this repository can find it.

`connect_sso_token_create` mints a login for whatever `client_id` the caller passes. It authenticates
the **caller**; it cannot authenticate the **visitor** the token is destined for, and it has no way
to tell whether the person who clicked owns that client account. A consuming system that takes a
client id from a request parameter, or omits the ownership check between its own session and its own
records, hands one customer a working login to another customer's panel account. Every log line here
will look completely ordinary: a trusted integration asked for a token and got one.

That check belongs to the integrator, it is not optional, and
[README §4](README.md#4-integrating-your-system) opens with it. If you are **writing** an
integration, read that warning before anything else. If you have **found** such a flaw in a specific
consuming system, report it to that project — not here — unless the flaw is that this project's
documentation led them into it, which is a real and welcome finding.

## Out of scope

- **A vulnerability in a consuming system**, including a missing ownership check on the client id it
  passes. Report those to that project; see the section directly above.
- Pre-existing ISPConfig **core** behaviour, which is reported upstream instead. Several controls
  here exist specifically to compensate for it — `checkPerm()` trusting client sessions, optional
  session regeneration at the login form, `affectedRows()` reading the connection rather than the
  statement — and those are documented, not defects in this repository.
- An operator granting `connect_sso_token_create` to the wrong remote user, or leaving that user's
  Remote Access IP list empty. Documented consequences of a documented grant.
- Running the panel over plain HTTP, or declaring `reverse_proxy_panel_allowed` on a panel that has
  no reverse proxy. The first is refused outright; the second is the operator overriding a safety
  check in a root-owned file.
- Anything that requires an existing administrator session on the panel to set up.
