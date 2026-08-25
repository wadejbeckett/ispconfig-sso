# Contributing to ispconfig-sso

Bug reports, fixes and ideas are welcome. This page is the practical guide; the *what it does and
why* lives in [README.md](README.md), and the reporting policy for anything security-sensitive is in
[SECURITY.md](SECURITY.md) — **read that one first if your finding is a vulnerability**, because it
should not arrive as a public issue or pull request.

This is one ISPConfig extension: a **single sign-on provider**. It registers one remote API function
that mints a one-time panel-login token, and one page that redeems it. It is deliberately
independent of any billing system — WHMCS, Blesta, FOSSBilling and hand-written scripts are all just
callers of the same contract, and none of them is privileged in this repository.

ISPConfig calls third-party add-ons *extensions*, and that is what this is. It installs an ISPConfig
**module** directory called `connectsso`; "module" in this document always means that ISPConfig
mechanism, never the project itself.

## The one thing to understand before changing anything

`interface/web/connectsso/` is an **authentication endpoint pair**. The mint function hands out a
password substitute, and the redemption page turns it into a panel session. Every check in those
files is load-bearing, and several of them exist because core's own behaviour is surprising — the
comments say which and why, with the core file and line number that makes it true.

So: **read the comment before deleting the code it explains.** If a check looks redundant, it is
usually the second half of a defence-in-depth pair (the admin refusal exists in *both* halves on
purpose), or it is guarding against something core does that is not obvious (`checkPerm()` returning
true for client sessions; `affectedRows()` reporting the previous statement's count).

## Ground rules

1. **Never modify an ISPConfig core file.** Everything ships inside `interface/web/connectsso/`.
   The only ISPConfig-owned state anything here writes is `sys_user.modules` — install and uninstall
   adding or removing the string `connectsso` on `typ = 'admin'` rows — plus the audit trail, which
   goes to `sys_log` and `auth.log` through core's own `$app->log()` and `$app->auth_log()`. No
   schema change to an existing table, no new column, no `sys_datalog` row. If a change needs a core
   patch, it belongs upstream instead.
2. **Names are frozen.** The module directory `connectsso`, the tables `connectsso_token` and
   `connectsso_attempt`, the redemption path `/connectsso/`, the function name
   `connect_sso_token_create` and its parameter names `session_id` / `client_id` / `bind_ip` are all
   installed state on live panels. The directory *is* the registration mechanism; the function name
   is the literal string sitting in `remote_user.remote_functions` on every panel that granted it;
   the JSON API maps request keys to parameter names by reflection. Renaming any of them silently
   breaks working installs and existing grants. `tests/run.php` asserts the function and parameter
   names for exactly this reason. Display strings — the grant checkbox label, the docs — are free.
3. **Exactly one public method** on `remoting_connectsso`. ISPConfig's auto-loader maps *every*
   public method of a `remote.d` class into the remote API's method map, so a second public method is
   a second remote function, whether you meant one or not. Helpers are `private`.
4. **Every refusal must be audited, and must mint nothing.** A refused attempt to create a password
   substitute must never be the one event recorded nowhere. Add the refusal to the table in
   `tests/run.php` in the same change — the harness counts entries, so a refusal added to the
   function without a table entry fails the build rather than slipping through unaudited.
5. **Never log a token or a token hash.** The point of hashing at rest is that a log reader cannot
   reconstruct a login. The harness asserts the clear token appears in no stored column and no log
   line.
6. **Audit lines are priority 2 (`LOGLEVEL_ERROR`), always.** `app.inc.php` `log()` silently drops
   anything below `$conf['log_priority']`, which every shipped install sets to 2. A security event
   logged at debug or warning priority is logged nowhere.
7. **Fail closed.** A missing config key, an `$app` without `getconf`, an unreadable ini, a session
   record that cannot prove what it is — every one of those must refuse, never default to permissive.
8. **The token lifetime stays under 60 seconds.** It covers one HTTP redirect. The harness asserts
   this; if a change needs a longer window, that is a design discussion in an issue first.
9. **PHP-5-flavoured style under `interface/`.** No namespaces, no `strict_types`, no typed
   properties, no short array syntax in the panel-side files — they load on every PHP version the
   host panel supports, and they sit beside ISPConfig's own code, which reads that way. The scripts
   under `bin/` and `tests/` are standalone CLI tools and are not bound by this.
10. **New SQL must survive core's `securityScan()`.** `db_mysql.inc.php` scans the final query string
    and, when it objects, `query()` returns false with nothing logged — a statement that trips it
    fails *silently and permanently*. `tests/run.php` replays that scanner over a transcribed list of
    every statement in the module; add yours to the list, and note that the tripwire counts SQL
    literals in the source, so it will tell you if you forgot.

## Testing a change

### The harness — always

```bash
php tests/run.php
```

No dependencies, no database, no panel, and nothing from any consuming project. It stands in for the
two core contracts the module depends on (the `remote.d` auto-loader and the `$app`/`db` surface) and
drives the mint function through every refusal path and the happy path. It must be green, and new
behaviour needs new assertions in it.

### Lint — always

```bash
find . -name '*.php' -not -path './.git/*' -print0 | xargs -0 -n1 php -l
```

### The real panel — for anything touching redemption

`interface/web/connectsso/index.php` is a top-level script that redirects and exits, so the harness
cannot execute it. It prints an 18-item manual checklist when it finishes: replay, expiry, IP
binding, the rate limit, both halves of the TLS gate, the 2FA hand-off, session-id rotation, the burn
race, the direct-request guards and the install/uninstall round trip. **Work through the items your
change touches on a test panel**, and say in the pull request which ones you ran and what you saw.

Install against a test panel with:

```bash
./install.sh --symlink /usr/local/ispconfig
```

`--symlink` serves the module straight out of your clone, so edits are live on the next request. The
installer refuses to symlink a directory containing **any** dot-entry or `node_modules`, because a
symlinked install is served *through* the link and those would be reachable over HTTP. The module
itself ships no dot-entries, so anything of the sort found there is foreign and a reason to stop.

**Never develop against a production panel.** This code mints panel logins.

## Reporting a bug

Open an issue with:

- your exact ISPConfig version (`Help → Version`, patch level included);
- the release or commit of this project you installed;
- whether the panel is behind a reverse proxy, and what `reverse_proxy_panel_allowed` is set to;
- what you called, and the fault code and message you got back;
- the relevant lines from **Monitor → System Log** and `/var/log/ispconfig/auth.log` — every refusal
  writes the real internal reason to both, which is usually the whole diagnosis.

**Never paste a token into an issue.** If one is still live, it is a working login.

Two checks before filing:

- **Is it the grant?** `You do not have the permissions to access this function.` from the mint
  function means either the checkbox is not ticked or you are calling with a client-login session
  rather than a remote user's. (Over SOAP that fault carries the code `permission_denied`; over JSON
  every fault code is flattened to `remote_fault`, so match on the message.)
- **Is it TLS?** `Single sign-on requires an encrypted (https) connection to the panel.` is the
  transport gate, not a bug. See the box at the top of the README.

If the problem turns out to be ISPConfig **core** rather than this project, take it to the
[ISPConfig bugtracker](https://git.ispconfig.org/ispconfig/ispconfig3/-/issues) or the
[HowtoForge forum](https://forum.howtoforge.com/) — and please link the issue here too, because
several of this project's checks exist to work around core behaviour and a fix upstream may let one
of them go.

## Adding your system to *Known integrations*

The README's last section lists systems that speak this contract. Open a pull request adding a row —
name, one sentence, link. There is no approval bar beyond it being real and working, and no
requirement that it be open source. Consumers are not dependencies; the list is a courtesy to people
looking for a starting point.

If you found the contract ambiguous while building, say so in the same pull request. That is a
documentation bug in [README.md §4](README.md#4-integrating-your-system), and it is worth more than
the list entry.

## Submitting a pull request

- Keep it small and focused — one fix or one feature.
- Say which harness assertions you added, and which manual checklist items you ran.
- If you changed anything under `interface/web/connectsso/`, say in one sentence what an attacker
  gains or loses from the change. If the answer is "nothing", say that — it is a fine answer, and
  writing it down is the point.
- Cite core by file and line for any new claim about ISPConfig's behaviour, the way the existing
  comments do, and name the version you verified against.
- By contributing you agree your work is licensed under this repository's
  [GPLv3 licence](LICENSE).
