# Changelog

All notable changes to **ispconfig-sso** are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

**What "breaking" means here.** The public surface of this project is not a PHP API — it is the
wire contract that consuming systems build against, plus the installed state on a live panel:

- the remote function name `connect_sso_token_create` and its parameter names
  (`session_id`, `client_id`, `bind_ip`) — the JSON API maps request keys to parameter names by
  reflection, so a rename breaks every client;
- the shape of the returned object (`token`, `path`, `expires_in`, `client_id`, `username`);
- the fault messages a caller can branch on;
- the module directory `connectsso`, the table names `connectsso_token` / `connectsso_attempt`,
  and the redemption path `/connectsso/`.

Changing any of those is a **major** version. Tightening a security control that a correct client
never depended on is a minor or patch release, and gets a `Security` entry saying so.

## [1.0.0] — unreleased

First release as a standalone project. Previously developed inside the
[ISPConfig Connect for WHMCS](https://github.com/wadejbeckett/ispconfig-connect-whmcs) repository as
`companion/ispconfig-sso`; extracted with its git history so that any billing system — Blesta,
FOSSBilling, WHMCS, something in-house — can consume it on equal terms.

The date lands when the first tag does.

### Added

- `connect_sso_token_create(session_id, client_id, bind_ip = '')` — a remote API function that mints
  a 45-second, single-use, optionally IP-bound panel-login token for one ISPConfig client. Registered
  through ISPConfig's own `remote.d` module auto-loader
  (`interface/lib/classes/remoting_handler_base.inc.php`), so **no core file is modified**.
- `/connectsso/` — the redemption endpoint. Burns the token and builds the same panel session
  `interface/web/login/index.php` builds, then redirects to the panel's `/index.php`. Accepts the
  token by `GET` (for a redirect) or `POST` (for an auto-submitting form, which keeps it out of
  access logs and browser history).
- `lib/remote.conf.php` — makes the grant a checkbox under System → Remote Users.
- `install.sh` / `uninstall.sh` — deploy or remove the module directory, create or drop the two
  tables, and add or remove `connectsso` in each admin's `sys_user.modules` (which is what makes the
  grant checkbox render). `--symlink`, `--no-assign`, `--no-schema`, `--keep-data`.
- `bin/connectsso_schema.php` (`--install` / `--drop` / `--check`) and `bin/connectsso_module.php`
  (`--assign` / `--unassign`) — the same steps as standalone, idempotent CLI tools.
- `tests/run.php` — a dependency-free harness that replays core's `remote.d` auto-loader against the
  module and drives the mint function through every refusal path and the happy path. 93 checks. It
  also prints the 18-item manual checklist for the redemption half, which cannot be covered without
  a real panel.
- README integration guide: the full API contract, detection via `get_function_list`, a worked
  plain-PHP example (curl to `remote/json.php`, then redirect), and the fault table.

### Security

Everything in this list is a deliberate property of 1.0.0, not a fix for a prior release.

- **Administrator accounts can never be minted for**, checked at mint *and* again at redemption, so
  a hand-inserted token row still cannot become an admin login.
- **Client-login API sessions are refused outright.** Core's `checkPerm()` returns true
  unconditionally for them, and any customer with `can_use_api = 'y'` can open one — trusting
  `checkPerm()` alone would have allowed cross-tenant panel takeover. The check fails closed: a
  session that cannot prove `client_login = 0` is refused.
- **TLS is required** in both halves; the gate steps aside only where the operator declared a reverse
  proxy in ISPConfig's own `security_settings.ini`, never on a request header.
- **Tokens are stored only as SHA-256**, are 256 bits of `random_bytes()`, and never appear in any
  log line or stored column.
- **Single use** is enforced by a conditional `UPDATE … WHERE used_at IS NULL` and its affected-row
  count, with an explicit check that the statement actually executed — `affectedRows()` alone would
  report the previous statement's count if the query never reached the server.
- **Two-factor authentication and forced password changes are preserved**, by handing the visitor to
  the panel's own `/login/otp.php` and `/login/force_password_change.php`.
- **Session fixation:** `session_regenerate_id(true)` is mandatory here and a failure to regenerate
  is fatal, where core's own login makes it optional.
- **Maintenance mode is honoured**, matching the panel's own login form.
- **Redemption is rate-limited** to 10 failed attempts per source address per 5 minutes, counting
  only refusals reached by presenting a token value that did not check out.
- **Every mint, every refusal in either half, and every sign-in is audited** to `sys_log` and
  `auth.log` at a priority a shipped install actually keeps.
- **Uniform refusals:** every token-related failure renders the identical 403 page, so the endpoint
  is never an oracle about someone else's token.
- **Direct-request guards** on every `.php` under `lib/`, which the stock vhosts do not deny.
