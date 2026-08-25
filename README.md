# ispconfig-sso — one-time panel login for ISPConfig

A **single sign-on provider for ISPConfig 3.x**. It adds one remote API function that mints a
short-lived, single-use panel-login token, and one page that redeems it and establishes the panel
session.

Anything that can call ISPConfig's remote API can use it: a billing system (WHMCS, Blesta,
FOSSBilling, something bespoke), a support desk, a provisioning script, an internal dashboard. It
has no opinion about who the caller is and no dependency on any of them — the whole interface is
one remote function and one URL, documented in [§4, *Integrating your system*](#4-integrating-your-system).

It exists because **ISPConfig core has no one-time-login API**, so every "Log in to panel" button
ever shipped had to store the customer's panel password and replay it into the login form. This
makes that unnecessary.

GPLv3. **No ISPConfig core file is modified**, read-only or otherwise — it installs into
`interface/web/connectsso/` through ISPConfig's own documented `remote.d` extension point and
creates two tables of its own.

> ### ⚠ The panel must be served over HTTPS
>
> A token is a **password substitute travelling in a URL**. Over plain HTTP the mint response, the
> redirect that carries the token and the panel session that follows are all readable by anything on
> the path — and single use plus a 45-second lifetime buy nothing against an interceptor who simply
> redeems the token before the customer's browser does.
>
> Both halves therefore **refuse to operate on a non-TLS request**. Minting answers
> `Single sign-on requires an encrypted (https) connection to the panel.`; the redemption endpoint
> refuses without touching the token. ISPConfig's own installer asks *"Do you want a secure (SSL)
> connection to the ISPConfig web interface"* and **defaults to yes** (`install/install.php:608`), so
> on a normal install this is already satisfied.
>
> **Behind a TLS-terminating reverse proxy** PHP sees the proxy's plaintext hop and cannot tell the
> difference, so the gate steps aside when — and only when — the operator has declared that topology
> in ISPConfig's own security settings:
> `reverse_proxy_panel_allowed` in the `[permissions]` section of
> `/usr/local/ispconfig/security/security_settings.ini`, set to anything other than the shipped
> `none`. That is a local file only root can write. No request header is ever trusted for this, and
> declaring it makes TLS termination the proxy's responsibility.

---

## 1. What it does, and what it does not

**It does:**

- register **one** remote API function, `connect_sso_token_create`, which mints a 64-hex-character
  token for one ISPConfig `client_id`, valid for **45 seconds**, redeemable **once**, and
  optionally bound to a single source IP address;
- serve **one** page, `/connectsso/`, which redeems that token and builds the same panel session
  `interface/web/login/index.php` builds — same session keys, same start module, same theme gate —
  then redirects to the panel's own `/index.php`;
- store tokens **only as SHA-256**, and audit every mint, every refusal and every sign-in to both
  `sys_log` and the panel's `auth.log`.

**It does not:**

- **Log anyone in as an administrator.** `sys_user.typ = 'admin'` is refused at mint *and* again at
  redemption. There is no flag, no configuration setting and no parameter that relaxes this. If you
  want an admin auto-login, this is the wrong project.
- **Bypass two-factor authentication.** A token replaces the *password*. If the target user has
  `otp_type != 'none'` the session is parked and the visitor is handed to the panel's own
  `/login/otp.php`, exactly as the login form does. A forced password change is honoured the same
  way.
- **Store, read, set or replay panel passwords.** It never touches `sys_user.passwort`.
- **Create anything.** The client and its panel user must already exist; this only mints a login for
  one that does.
- **Act as an identity provider.** No SAML, no OIDC, no OAuth, no cross-application session. The one
  and only thing a token can do is open a session on *this* panel, for *one* named account.
- **Add anything to the panel UI.** No navigation entry, no settings page, no dashlet. It ships no
  `lib/module.conf.php`, which is what keeps it out of `nav.php`.
- **Require a cron job.** Both tables garbage-collect themselves inline.
- **Work over plain HTTP.** See the box above.
- **Bound the session it creates.** Once redeemed, the result is an ordinary panel session with the
  panel's own timeout — the 45 seconds is the hand-off window, not a session lifetime.

## 2. Why it has to exist

Verified across the ISPConfig 3.3.1p1 tree:

- `client_login_get()` only *validates* a username/password pair.
- `login($user, $pass, true)` mints a **remote API session** (a row in `remote_session`), not a
  panel session — the panel's own login is `$_SESSION['s']['user']`, written by
  `interface/web/login/index.php`.

There is no third option in core. So every integration that ever offered a "log in to panel" button
did it the only way core allowed: keep the customer's panel password somewhere and post it into the
login form. That is why those integrations leaked passwords into HTML, and it is the specific thing
this project exists to make unnecessary.

### How it attaches without touching core

ISPConfig's remoting handler auto-loads extra remote API classes from modules
(`interface/lib/classes/remoting_handler_base.inc.php:47`):

```php
$this->load_remoting_classes(realpath(__DIR__) . '/remote.d/*.inc.php');                    // core
$this->load_remoting_classes(realpath(__DIR__) . '/../../web/*/lib/classes/remote.d/*.inc.php'); // modules
```

Each match is `include_once`'d, the class `remoting_<filename>` is instantiated, and **every public
method** of it joins the handler's method map. That is the whole integration: dropping
`interface/web/connectsso/` into the panel registers `connect_sso_token_create`, and deleting the
directory unregisters it. Nothing is patched, nothing is hooked, and an ISPConfig upgrade cannot
overwrite a change we did not make.

Two consequences of that mechanism, both deliberate here:

- `remoting_connectsso` extends `remoting`, so it inherits `checkPerm()` and `getSession()` — the
  same permission and session code every built-in remote function uses, rather than a second
  hand-written copy that could drift from it. Inheriting also means `get_class_methods()` sees the
  public methods of `remoting` itself; the handler re-pins `login`, `logout` and
  `get_function_list` to the core instance immediately afterwards (lines 50–52), while
  `server_get`, `server_get_all` and `__construct` end up dispatched to this class. They are
  inherited verbatim, so behaviour is unchanged — and this already happens between the built-in
  classes on a stock install, where `remoting_sites` (loaded last) owns them today. This class
  therefore declares exactly **one** public method of its own, and `tests/run.php` asserts that it
  takes over nothing else.
- Because the function is registered in the method map, `get_function_list` reports it. That is how
  a client detects that SSO is available on a panel — see [§4.2](#42-detecting-whether-a-panel-has-it).

**Names are frozen.** The module directory (`connectsso`), the two table names
(`connectsso_token`, `connectsso_attempt`), the remote function name
(`connect_sso_token_create`) and its three parameter names are all installed state on live panels:
the directory *is* the registration mechanism, the function name is the literal string stored in
`remote_user.remote_functions` on every panel that has granted it, and the JSON API maps request
keys to parameter names by reflection. Renaming any of them silently breaks working installs and
grants, so they will not change. Only display strings — the grant checkbox label, this document —
are free to be reworded.

## 3. Install and remove

```sh
./install.sh                       # /usr/local/ispconfig
./install.sh /path/to/ispconfig    # elsewhere
./install.sh --symlink             # development: serve straight from the clone
```

It copies `interface/web/connectsso/` into the panel, creates the module's two tables, and adds
`connectsso` to each admin's `sys_user.modules`.

That last step is what makes the permission checkbox appear: System → Remote Users builds its
Functions list by including `<module>/lib/remote.conf.php` for the modules named in the **logged-in
admin's** module column (`interface/web/admin/form/remote_user.tform.php:36-45`). Without it the
checkbox never renders — and saving that form would then *drop* the grant, because a `CHECKBOXARRAY`
field is rebuilt from the checkboxes that were posted (`tform_base.inc.php:828-833`, the `VARCHAR`
case of `_encode()`: an array is `implode()`d, and nothing posted stores `''`).

It does **not** put anything in the panel navigation: `nav.php` renders only modules that ship
`lib/module.conf.php`, and this one deliberately ships none.

**Then grant it**, which the installer will not do for you:
System → Remote Users → your API user → Functions →
tick *Panel single sign-on (one-time login token)* → Save.
(If the box is missing, log out and back in — the list is built from the logged-in admin's modules.)

**And confirm the panel is HTTPS.** Both halves refuse on a plaintext request; see the box at the
top of this file, including what to set when a reverse proxy terminates TLS for you.

Uninstall reverses all three steps:

```sh
./uninstall.sh              # also drops the tables (they hold nothing but live tokens)
./uninstall.sh --keep-data
```

Removing `interface/web/connectsso/` is what unregisters the function — from the very next remote
API request, `connect_sso_token_create` is simply not in the method map any more. Nothing of
ISPConfig's own was changed, so there is nothing to restore. The uninstaller deliberately does *not*
rewrite anyone's `remote_user.remote_functions`: a grant for a function that no longer exists is
inert, and rewriting other people's permission rows is not an uninstaller's job.

### Known caveat

Saving an admin's CP-user record rewrites `sys_user.modules` from the checkbox list on that form,
which is built only from directories that have `module.conf.php`
(`interface/web/admin/form/users.tform.php:90`) — so it silently drops `connectsso`. If the SSO
checkbox disappears from the Remote Users form, re-run `./install.sh`, or just:

```sh
php bin/connectsso_module.php --assign /usr/local/ispconfig/interface/lib/config.inc.php
```

Token minting and redemption are unaffected by this; only the checkbox is.

## 4. Integrating your system

This is the part that makes the project worth shipping separately. Everything below is the complete
contract — there is nothing else to learn, and no library to depend on.

> ### ⚠ You own the authorisation decision. Read this before you write any code.
>
> **A token proves nothing about who asked for it.**
>
> `connect_sso_token_create` mints a login for whatever `client_id` you pass it. It cannot know
> whether the person clicking the button in your system actually owns that client account. It checks
> that **you** are allowed to mint tokens; it does not, and cannot, check that **they** are allowed
> to receive this one. That check is yours, it is not optional, and skipping it is the one way to
> turn this project into a vulnerability.
>
> The failure mode is not subtle. A customer opens `/panel-login?client_id=57`, your code passes 57
> through to the mint call, and they are signed in to somebody else's hosting account with full
> control of its websites, mailboxes, databases and DNS. The panel has no way to notice: as far as it
> is concerned, a trusted integration asked for a token and got one.
>
> So, in your own code, on every single mint:
>
> 1. Identify the visitor from **your own session**, never from a request parameter.
> 2. Look up the ISPConfig `client_id` **from your own records**, for that authenticated identity —
>    the service or account row where you already store the panel client id.
> 3. Confirm they are entitled to that specific service *right now*: it is theirs, and it is active.
> 4. Only then mint, and redirect immediately.
>
> Never take a client id, a panel username or a panel base URL from a query string, a form field, a
> cookie or a JavaScript call. If your SSO entry point accepts an identifier as input, that
> identifier is an authorisation bypass waiting to be found.
>
> The same reasoning applies to *staff* SSO: an admin in your billing system opening a customer's
> panel is fine, but it is your permission model that decides which staff may do it, and your audit
> log that should record that they did. The panel only records that your integration minted a token.

### 4.1 The contract

**Function**

```
connect_sso_token_create(session_id, client_id, bind_ip = '')
```

| Parameter | Type | Meaning |
|---|---|---|
| `session_id` | string | An ordinary ISPConfig remote API session, from `login()`. Must be a **remote user's** session, not a client login (see below). |
| `client_id` | int | The `client.client_id` to log in as. Must be > 0. |
| `bind_ip` | string | Optional. The address the token may be redeemed **from** — the *end user's browser*, not your server's. `''` leaves it unbound. |

**Returns** (a JSON object / associative array):

```json
{
  "token": "9f2c…64 lowercase hex chars…a1",
  "path": "/connectsso/",
  "expires_in": 45,
  "client_id": 12,
  "username": "acmeltd"
}
```

| Field | Use it for |
|---|---|
| `token` | The credential. Exactly 64 lowercase hex characters today; treat it as opaque and validate it against a conservative charset before putting it in a URL. |
| `path` | Where to send the browser, relative to the panel's base URL. **Reported rather than assumed**, so the endpoint can move without a client release. Validate it as a plain local path (see the example) — that check is your open-redirect guard. |
| `expires_in` | Seconds of validity, currently 45. Useful for a "this link has expired" message; the panel is the authority, not your clock. |
| `client_id` | Echo of what you asked for, as an int. |
| `username` | The panel username the token logs in as. Display-only — handy for "You will be signed in as *acmeltd*". |

**Semantics you must build around**

1. **Single use.** The first redemption burns it; the second is refused. Never hand the same token
   to two things.
2. **45 seconds.** Mint it *at click time*, in the request that redirects. Do not mint on page
   render, do not put one in an email, do not cache one, do not queue one.
3. **One live token per client.** Minting deletes that client's previous unredeemed token. Two
   "Log in" clicks in quick succession means the first link stops working.
4. **The browser redeems it, not you.** Your server never fetches `path`; it only redirects the
   customer's browser there.
5. **The panel's public base URL may differ from your API URL.** ISPConfig's API commonly lives on
   `:8080` while customers reach the panel by another hostname or port. Make the base URL of the
   redirect configurable rather than derived from your API endpoint.

**Transport.** It is an ordinary ISPConfig remote function, so:

- **`remote/json.php` — recommended.** The method name is the first query-string key; parameters go
  in the JSON request body **keyed by parameter name** (`interface/lib/classes/json_handler.inc.php`
  maps them by reflection). A missing key is passed as `null`.
- **`remote/index.php` — SOAP.** Works too, with positional arguments, via any ISPConfig SOAP client.
- **`remote/api/v1/…` — REST. Cannot reach this function.** That handler builds the method name from
  the HTTP verb (`_add`, `_get`, `_update`, `_delete`), and nothing it can build ends in `_create`.

**Prerequisites on the panel side**

| Requirement | Where |
|---|---|
| This project installed | `./install.sh` |
| `connect_sso_token_create` granted to your API user | System → Remote Users → Functions |
| *Server functions* granted, **only if** you want to probe with `get_function_list` | same form; that checkbox is the one carrying `get_function_list` (`interface/web/admin/lib/remote.conf.php:3`) |
| Remote API enabled | `remote_api_allowed = yes` in `security_settings.ini`; otherwise **both** `json.php` and `index.php` refuse every call with a plain-text `Remote API is disabled in security settings.` |
| Your caller's address in the user's Remote Access IP list | System → Remote Users → Remote Access IPs (or leave it empty to allow any address) |
| Panel served over HTTPS | see the box at the top |

### 4.2 Detecting whether a panel has it

Call `get_function_list` and look for `connect_sso_token_create` in the result. That call returns
the handler's **whole** method map rather than the caller's own grants
(`remoting.inc.php:685-692` returns `$this->_methods`), so it is a true presence probe.

It is **not** an ungated call — it is permission-checked like any other
(`checkPerm($session_id, 'get_function_list')`, `remoting.inc.php:687`), and the grant lives in the
**Server functions** checkbox. Only `login` and `logout` are ungated. So there are three outcomes,
and a good client tells them apart:

| Result | Means |
|---|---|
| the name is in the list | SSO is installed. It may still not be granted *to you* — you find that out by calling it. |
| the name is absent | SSO is not installed on this panel. Hide the button; this is not an error. |
| the probe itself is refused as a permission failure | You lack *Server functions*. Report it as **SSO unavailable**, never as "SSO is not installed" — you genuinely do not know. Over SOAP this arrives as `permission_denied`; over JSON the code is flattened to `remote_fault` and you match on the message (see [§4.5](#45-faults)). |

Calling `connect_sso_token_create` on a panel without it installed returns ISPConfig's own
`invalid_method` (`Method connect_sso_token_create does not exist`), which is equally usable as a
probe if you would rather skip the extra round trip.

### 4.3 Worked example — plain PHP, no dependencies

Copy this into any system. It logs in, mints, and redirects; there is nothing else to it.

```php
<?php
/**
 * Minimal ISPConfig single sign-on consumer.
 * Run this from the request that handles the customer's "Log in to panel" click.
 */

$apiUrl    = 'https://panel.example.com:8080/remote/json.php'; // the remote API
$panelBase = 'https://panel.example.com:8080';                 // what the BROWSER can reach
$apiUser   = 'billing';
$apiPass   = getenv('ISPCONFIG_API_PASSWORD');
// The panel-side client.client_id. In real code this MUST come from your own
// database, looked up for the already-authenticated visitor — never from the
// request. See the warning at the top of section 4: that lookup is the entire
// security boundary on your side of this call.
$clientId  = lookup_client_id_for_logged_in_user();
$bindIp    = '';                        // or the END USER's address; '' = unbound

/**
 * One ISPConfig JSON API call. The method name is the first query-string key;
 * parameters are a JSON body keyed by the function's own parameter names.
 */
function ispconfig_call($apiUrl, $method, array $params) {
    $ch = curl_init($apiUrl . '?' . $method);
    curl_setopt_array($ch, array(
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($params),
        CURLOPT_HTTPHEADER     => array('Content-Type: application/json'),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        // The panel is about to hand back a password substitute. Verify that it
        // really is your panel: never turn these off in production.
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ));
    $body = curl_exec($ch);
    if ($body === false) {
        $err = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('ISPConfig unreachable: ' . $err);
    }
    curl_close($ch);

    $decoded = json_decode($body, true);
    if (!is_array($decoded) || !isset($decoded['code'])) {
        throw new RuntimeException('ISPConfig returned a non-API response');
    }
    if ($decoded['code'] !== 'ok') {
        // 'remote_fault' carries this project's messages; 'invalid_method'
        // means the panel does not have it installed.
        throw new RuntimeException($decoded['code'] . ': ' . $decoded['message']);
    }

    return $decoded['response'];
}

$sessionId = ispconfig_call($apiUrl, 'login', array(
    'username' => $apiUser,
    'password' => $apiPass,
));

$ticket = ispconfig_call($apiUrl, 'connect_sso_token_create', array(
    'session_id' => $sessionId,
    'client_id'  => $clientId,
    'bind_ip'    => $bindIp,
));

ispconfig_call($apiUrl, 'logout', array('session_id' => $sessionId));

// Validate what came back before it goes anywhere near a URL. Note the /D on
// both patterns: without it PCRE's '$' also matches BEFORE a final newline, so
// a value ending in a raw LF would pass and then land in a Location: header.
if (!isset($ticket['token']) || !preg_match('/^[a-f0-9]{32,256}$/D', $ticket['token'])) {
    throw new RuntimeException('no usable one-time token was returned');
}
$path = isset($ticket['path']) && $ticket['path'] !== '' ? $ticket['path'] : '/connectsso/';
// A single leading slash and safe path characters only. THIS is the open-redirect
// guard: it rejects '//evil.example/', 'https://evil.example/', 'connectsso/'
// (relative), anything carrying '?' or '#', and '../'.
if (!preg_match('#^/(?!/)[A-Za-z0-9._~/-]*$#D', $path) || strpos($path, '..') !== false) {
    throw new RuntimeException('the panel reported an unusable endpoint path');
}

header('Location: ' . $panelBase . $path . '?token=' . rawurlencode($ticket['token']));
exit;
```

Two refinements worth making in a real integration:

- **Reuse the API session.** `login()` writes a row to `remote_session` and is rate-limited by core
  (10 failures per 5 minutes, `remoting.inc.php:94`). A long-lived integration should cache the
  session id and re-login only when a call fails as expired, rather than logging in per click.
- **Prefer POST for the hand-off** if you can render an interstitial page. The endpoint accepts the
  token as a **POST** parameter as well as a query-string one, so an auto-submitting form keeps the
  token out of the panel's access log and the customer's browser history:

  ```html
  <form id="sso" method="post" action="https://panel.example.com:8080/connectsso/">
    <input type="hidden" name="token" value="…">
  </form>
  <script>document.getElementById('sso').submit();</script>
  ```

  The trade-off is that the token now passes through your own page's HTML instead. Pick whichever
  log you would rather it landed in; a redirect is the simpler default and is what the 45-second
  lifetime is sized for.

### 4.4 About `bind_ip`

Pass the **end user's** address as your system sees it — the browser redeems the token, your server
only mints it. The comparison is on the binary form (`inet_pton` + `hash_equals`), so equivalent
spellings of the same address match and nothing else does.

Bind only when the panel and your system will genuinely see the same address. A CDN or reverse proxy
in front of either, or an IPv4/IPv6 asymmetry, and **every** login fails. Unbound is the safe
default; bound is stronger where the topology allows it. Note also that the panel reads
`REMOTE_ADDR` only — never `X-Forwarded-For` — so behind a proxy you must make the proxy set
`REMOTE_ADDR` (`mod_remoteip`, nginx `realip`) or leave binding off.

### 4.5 Faults

Everything below arrives as a `SoapFault`, flattened by the JSON handler to
`{"code":"remote_fault","message":"…"}` with the message preserved. Every one of them is written to
`sys_log` and `auth.log` **first**, with the real internal reason; the caller only ever sees the
message in this table.

| Message | Cause |
|---|---|
| `You do not have the permissions to access this function.` | grant not ticked, **or** the session is a client login (`login(u, p, true)`) rather than a remote user's — client sessions can never mint (core wording for both, on purpose) |
| `Single sign-on requires an encrypted (https) connection to the panel.` | the API request did not arrive over TLS and no reverse proxy is declared — see the box at the top |
| `The client id must be an integer greater than zero.` | bad `client_id` |
| `The bind IP address is invalid.` | `bind_ip` is not a literal IP |
| `There is no panel user for this client id.` | no `sys_user` row with that `client_id` |
| `Single sign-on is not available for administrator accounts.` | target is an admin |
| `The panel user for this client is not active.` | `sys_user.active != 1` |
| `The client account is locked; single sign-on is refused.` | `client.locked = 'y'` or `client.canceled = 'y'` |

Not from this project, but you will meet them on the same call:

- `invalid_method` — a **JSON-handler** code, meaning the panel does not have this project installed.
  Together with `invalid_data` it is one of the few codes that is genuinely its own; treat it as the
  cheap "not installed" signal.
- core's own `login_failure_limit` and `maintenance_mode` faults from `login()`. Over SOAP those
  arrive as their own fault codes; **over JSON they flatten to `remote_fault` like everything else**,
  so match on the message, not the code. That flattening is why a JSON client cannot branch on
  `permission_denied` either — see the third row of the table in [§4.2](#42-detecting-whether-a-panel-has-it).
- a plain-text `Remote API is disabled in security settings.` — not JSON at all, because
  `remote/json.php` `die()`s before the handler runs when `remote_api_allowed` is not `yes`. A client
  that assumes every response is JSON will fail to parse this one; say so in your error message
  rather than reporting "invalid response".

Refusals the **visitor** meets at the redemption endpoint are deliberately uniform: every
token-related failure renders the same 403 page. Your side never learns which one it was, by design
— see [§5](#5-security-model).

## 5. Security model

This is an **authentication bypass primitive by design**: a token is a password substitute. The
design assumes it will leak eventually and makes a leaked token worth as little as possible.

**Who may mint**
- Only a **remote user's** API session. Core's `checkPerm()` is *not* sufficient authorisation
  here: it returns true unconditionally for any *client login* session
  (`remoting.inc.php:542-547`, "permissions are checked at an other place"), and any customer
  whose client record has `can_use_api = 'y'` can open one with `login(user, pass, true)`
  (`remoting.inc.php:99-156`). The mint function therefore re-reads the session and refuses
  `client_login` sessions outright — otherwise one API-enabled customer could mint a panel login
  for **any other** non-admin client on the panel. The refusal reuses core's permission wording
  and is written to both audit logs.
- Only over TLS, or on a panel whose operator has declared a reverse proxy in
  `security_settings.ini`. See the box at the top of this file.

**Who may be minted FOR — the exact boundary**

The only account class the module refuses is `sys_user.typ = 'admin'`, checked at mint **and** again
at redemption. Everything else on the panel is mintable, and that is a wider set than "customers":

- **Resellers are mintable.** ISPConfig does not give a reseller its own user type — every client the
  API creates gets `$type = 'user'` (`remoting_lib.inc.php:329`), and `limit_client > 0` merely adds
  the `client` module to that user's module list (`:311-313`). A token for a reseller therefore opens
  a panel session that can create, edit, suspend and delete **that reseller's sub-clients** and change
  their passwords. If you sell reseller plans through your billing system this is the feature working
  as intended; if you did not realise resellers were in scope, this is the sentence to re-read.
- A client whose `sys_user` row is shared with other services, or hand-created in the panel, is
  mintable too — the mint targets `client_id`, and takes the lowest `sys_user.userid` carrying it.
- Admin accounts are refused in both halves. The redemption-side check is not redundant: it means a
  hand-inserted row in `connectsso_token` still cannot become an admin login.

So the blast radius of the grant is **every non-administrator panel account, resellers included** —
not "customers". Size the grant accordingly (see *A leaked API grant is a leaked panel*, below).

**The token itself**
- 32 bytes from `random_bytes()` (256 bits), hex-encoded. Not `uniqid`, not `mt_rand`, not a hash of
  anything predictable.
- Stored **only as SHA-256**. A read of `connectsso_token` — a database dump, a backup, a SQL
  injection elsewhere in the panel — yields no usable login.
- Returned to the API caller once and never logged. The module writes an audit line naming the
  client and the panel user; it never writes the token or its hash.

**Lifetime and use count**
- **45 seconds** (`CONNECTSSO_TOKEN_TTL`; the test suite fails the build if it is set above 60). It covers one HTTP redirect, nothing more.
- **Single use.** The guard is a conditional `UPDATE … WHERE used_at IS NULL` whose affected-row
  count decides the winner — atomic in the database, so two simultaneous redemptions cannot both
  succeed. The `used_at` check before it is a fast path, not the lock. The endpoint also verifies
  the `UPDATE` actually *executed* before trusting the count: ISPConfig's `affectedRows()` reads
  `mysqli_affected_rows()` off the connection, which still reports the previous statement when a
  query is rejected before reaching the server (`db_mysql.inc.php:507-512`), so a failed burn
  refuses rather than proceeds.
- **One live token per client.** Minting deletes any unredeemed predecessor, which caps how many
  redeemable tokens can accumulate and means an abandoned SSO click cannot be redeemed later from a
  browser history entry.
- Redeemed rows are kept for an hour so a replay is *recognisably* a replay and gets audited as one,
  then garbage-collected — on the next mint, and at the start of the next redemption. There is no
  cron job to install.

**Binding**
- Always bound to one `client_id`/`sys_userid`.
- Optionally bound to a source IP — see [§4.4](#44-about-bind_ip) for when that is a good idea.
- Binding is checked **before** the token is burned, on purpose: someone who scraped a token from a
  log should not be able to invalidate the real customer's link just by opening it from the wrong
  address.

**Redemption endpoint**
- **TLS first.** A request that did not arrive over TLS is refused before the token is looked at,
  before the rate limiter, before anything — see the box at the top. It costs no rate-limit budget:
  it is a server-configuration refusal, not a guess at somebody's token.
- Rate-limited by source address before the token is looked at: 10 failures per 5 minutes, in the
  module's own `connectsso_attempt` table. That is the budget ISPConfig's **remote API** applies to
  `attempts_login` (`remoting.inc.php:94` at login, `:578` on every session lookup), and this
  endpoint matches it. Note that the panel's own **login form** is stricter and different —
  more than 5 failures within 1 minute (`login/index.php:61-68`) — so "same as ISPConfig" is not one
  number; this endpoint deliberately follows the API's. As in core, a request that arrives already at
  the limit is refused *without* being counted, so hammering does not extend the block.
- **What counts, exactly.** A failure counts when it was reached by **presenting a token value that
  did not check out**: malformed, unknown, expired, replayed, IP-binding mismatch, or a burn that did
  not take. Those are the guessing paths, and they are the ones the budget bounds.

  Nothing else counts, and the two kinds of "nothing else" are worth naming:
  - **Before the token is read at all** — the TLS refusal, and a request that arrives already at the
    limit. Neither says anything about a token.
  - **After the token checked out and was burned** — maintenance mode, a panel user that vanished or
    went inactive, a client suspended in the seconds since minting, a session that could not be
    started or regenerated. Each of these costs a genuine, already-spent token to reach, so they are
    useless for guessing.

  Counting either kind would let one server-configuration mistake, one maintenance window or one
  suspended customer exhaust the shared budget of every visitor behind the same address — which,
  behind a proxy that does not set `REMOTE_ADDR`, is everyone. All of them are still audited; the
  rate limiter is a guessing bound, not the audit trail.
- Rejections are indistinguishable to the visitor: every token-related refusal — malformed, unknown,
  expired, replayed, IP-mismatched, failed burn — produces the identical 403 page. The specific
  reason goes to the audit log only, so the page is never an oracle about someone else's token. The
  two refusals that carry a different status say nothing about a token either: 429 for the rate limit
  and 503 for maintenance mode, both properties of the server rather than of the link.
- **Session fixation:** `session_regenerate_id(true)` before anything is written to the session, and
  a failure to regenerate is fatal. ISPConfig's own login makes this optional — `session_regenerate_id`
  in the `[permissions]` section of `/usr/local/ispconfig/security/security_settings.ini`, a
  server-side file, not a panel form (`login/index.php:96-102`, because of core issue #3827). Here it
  is mandatory, because a token-based login with an attacker-chosen session id is worse than no SSO
  at all.
- **Open redirect:** the destination is a fixed `/index.php`. The request cannot influence where it
  lands. The other half of that guard belongs to the client: validate the `path` the panel reports
  before building a redirect from it, as [§4.3](#43-worked-example--plain-php-no-dependencies) does.
- **Two-factor authentication is preserved.** If the target user has `otp_type != 'none'`, the
  session is parked in `$_SESSION['s_pending']` and the visitor is handed to the panel's own
  `/login/otp.php`, exactly as `login/index.php` does. An SSO link replaces the password, not the
  second factor. A forced password change (`force_password_change_days`) is honoured the same way.
- **State is re-checked at redemption**, not just at minting: the panel user must still exist, still
  be active, still not be an admin, and the client must still not be locked. Seconds are enough for
  a suspension to land.
- **Maintenance mode is honoured.** The panel's own login form refuses every non-admin login while
  maintenance mode is on (`login/index.php:79`, honouring `maintenance_mode_exclude_ips`); the
  redemption endpoint applies the same gate, so an SSO link cannot walk a customer past a closed
  panel. The refusal is a 503.
- The rate-limit counter is a single atomic `INSERT … ON DUPLICATE KEY UPDATE` on the `ip_hash`
  primary key, so parallel rejected redemptions cannot race the counter and be under-counted.
- The PHP files under `lib/` sit inside the panel's document root. Both stock vhost templates serve
  `interface/web/`; the Apache one denies only `*.lng`
  (`install/tpl/apache_ispconfig.vhost.master`, `<FilesMatch "\.lng$">`), and the nginx one denies
  `*.lng` and dotfiles (`install/tpl/nginx_ispconfig.vhost.master`, `location ~ /\.`) — neither
  denies a `.php` under `lib/`. So each such file carries a direct-request guard:
  requested over HTTP without the panel bootstrap (`ISPC_ROOT_PATH`), it answers 404 and stops —
  no fatal, no path disclosure. An `.htaccess` would not be reliable here (`AllowOverride None`
  in the mpm_itk vhost; nginx ignores it), which is why the guard is in the files themselves.
- `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
  `X-Robots-Tag: noindex` on every response.

**What is deliberately NOT claimed**
- **The calling system's authorisation is not checked, and cannot be.** This module verifies the
  *caller* — a granted remote user, over TLS — not the *visitor*. Nothing on the panel side can tell
  whether the person who clicked owns the `client_id` that was passed. An integration that takes a
  client id from a request parameter is exploitable, it will look completely normal in every log
  here, and no setting in this project can protect against it. See the warning at the top of
  [§4](#4-integrating-your-system); it is the most important paragraph in this document.
- **The token appears in the panel's access log.** A browser redirect is a GET, so the token is in
  the URL. That is inherent to the pattern (cPanel and Plesk one-time-login URLs have the same
  property) and is why the token is single-use, expires in under a minute, and is stored hashed.
  The endpoint also accepts the token by **POST**, so a caller able to render an auto-submitting
  form can keep it out of access logs and browser history entirely.
- **The TLS gate is a check on the connection PHP sees, not a proof of end-to-end encryption.** It
  refuses the case that is unambiguously wrong (a plaintext request to the panel itself). It cannot
  see the hop between a browser and a reverse proxy, or between the proxy and the panel; where the
  operator declared `reverse_proxy_panel_allowed`, both of those are the operator's to get right. It
  also says nothing about the *calling system's* side of the connection — that end must verify the
  panel's certificate itself (`CURLOPT_SSL_VERIFYPEER` in the example above, or whatever your client
  library calls it).
- **`REMOTE_ADDR` only.** `X-Forwarded-For` and friends are client-supplied and are never consulted.
  Behind a reverse proxy, make the proxy set `REMOTE_ADDR` (`mod_remoteip`, nginx `realip`), or
  leave IP binding off; otherwise the rate limiter buckets every visitor together and binding
  compares against the proxy.
- **Login CSRF.** As with any SSO link, someone who can make a victim's browser open *their* token
  lands that victim in *their* panel account. The session replacement makes this loud rather than
  silent, and IP binding blocks it where topology allows, but it is not fully preventable in a
  redirect-based flow.
- **A leaked API grant is a leaked panel.** A remote user holding `connect_sso_token_create` can
  mint a login for **every non-administrator account on the panel, resellers included** — see
  *Who may be minted FOR* above. Grant it only to the API user your integration uses, and keep
  that user's Remote Access IP list populated. Note what that list actually is: ISPConfig resolves
  any hostname in it with `dns_get_record()` **on every login**
  (`remoting.inc.php:173-189`), with no caching and no failure handling — a hostname entry makes your
  DNS an authorisation input, and a resolver failure silently drops the entry and locks the caller
  out. Prefer literal addresses.

## 6. What it writes

Two tables, both module-owned, neither referenced by anything in ISPConfig:

| Table | Contents |
|---|---|
| `connectsso_token` | SHA-256 of live/just-used tokens, target user, client, optional bind IP, timestamps |
| `connectsso_attempt` | `md5(REMOTE_ADDR)` → failed-redemption counter for the 5-minute window |

Neither survives uninstall by default, and losing them costs nothing: everything in them expires
within a minute (tokens) or five (rate-limit buckets).

It writes to exactly two things of ISPConfig's own, and both are worth naming precisely:

- **`sys_user.modules`** — the install/uninstall scripts add or remove the string `connectsso` on
  `typ = 'admin'` rows, which is what makes the grant checkbox render. Nothing at runtime touches it.
- **`sys_log`**, through core's own `$app->log()`, plus the panel's `auth.log` file through
  `$app->auth_log()` — the audit trail described below. These are appends to ISPConfig's logging,
  made through ISPConfig's own API, exactly as a core remote function's own log lines are.

Those two are the whole of it. Beyond them and the module's own two tables, nothing in this project
writes ISPConfig-owned state: no schema change to an existing table, no new column, no row in
`sys_datalog`.

Audit lines go to `sys_log` (Monitor → System Log) for every mint, every refusal in **either** half —
including a call from a remote user that does not hold the grant — and every successful sign-in.
Core will not cover that first case for you: `checkPerm()`'s own `REMOTE-LIB DENY` line is written at
`LOGLEVEL_WARN` (`remoting.inc.php:553`), which the priority rule below discards on a shipped
install, so this module writes its own.

They are written at **priority 2 (`LOGLEVEL_ERROR`) on purpose**: `app.inc.php` `log()` silently
drops anything below `$conf['log_priority']`, and the installer sets that to 2 on every shipped
distribution (`install/tpl/config.inc.php.master:145`, `install/dist/conf/*.conf.php:39`) — an
audit line at debug or warning priority would be recorded nowhere. Token **issuance**, every
**refusal** and every **sign-in** additionally go to the panel's `/var/log/ispconfig/auth.log`,
alongside ISPConfig's own login records, so the trail survives even a panel whose `sys_log` is
pruned. None of these lines contain a token or a token hash.

## 7. Layout

```
interface/web/connectsso/
├── index.php                                  the redemption endpoint
└── lib/
    ├── connectsso_lib.inc.php                 constants + helpers shared by both halves
    ├── remote.conf.php                        makes the grant a checkbox in the panel UI
    └── classes/remote.d/connectsso.inc.php    class remoting_connectsso — the mint function
bin/connectsso_schema.php                      create / drop / check the two tables
bin/connectsso_module.php                      add / remove 'connectsso' in sys_user.modules
sql/install.sql, sql/uninstall.sql             the schema itself
tests/run.php                                  standalone harness (no panel, no database)
install.sh, uninstall.sh
```

The PHP under `interface/` is written in ISPConfig's own PHP-5-compatible style (no namespaces, no
`strict_types`, no typed properties) so it loads on every panel its host supports. The scripts under
`bin/` are standalone CLI tools and only need a PHP with `mysqli`.

## 8. Verifying it

```sh
php tests/run.php
```

A standalone harness — no panel, no database, no test framework, no dependency on any consuming
project. It replays core's remote.d auto-loader against this module (so a rename or an accidental
second public method fails loudly), and drives the mint function through every refusal path and the
happy path against a stand-in for `$app`, asserting among other things that:

- the clear token appears in **no** stored column and in **no** log line;
- the wire parameter names are still `session_id`, `client_id`, `bind_ip` — the JSON API maps
  request keys to parameter names by reflection, so renaming one would break every client;
- the TLS gate refuses plaintext and steps aside only for a declared reverse proxy;
- **every** refusal writes an audit line to both `sys_log` and `auth.log` and mints nothing — that
  one is table-driven, so a refusal added to the function without being added to the table fails the
  count assertion rather than slipping through unaudited;
- every SQL statement in the module survives core's `securityScan()`.

What it cannot cover is the redemption endpoint, which is a top-level script that redirects and
exits. That half is verified by hand on a real panel; the harness prints the 18-item checklist when
it finishes (replay, expiry, IP binding, rate limit, TLS gate, 2FA hand-off, session-id rotation, and
the install/uninstall round trip).

## 9. Compatibility

Developed and verified against **ISPConfig 3.3.1p1**, whose source is cited inline throughout — that
is the only version any claim here has been checked against. The extension point it depends on is
`interface/lib/classes/remoting_handler_base.inc.php`; `install.sh` checks that the file exists and
that it still globs `web/*/lib/classes/remote.d`, and refuses (or warns) where it does not, rather
than installing something that would silently never register. Everything the module reads from core —
`sys_user`, `client.locked` / `client.canceled`, the session keys written by `login/index.php`, the
OTP hand-off — is long-standing, but nothing here is upstream API: **re-verify after a major
ISPConfig upgrade**, and treat this README's line-number citations as version-specific.

## 10. Known integrations

Systems known to speak this contract:

| Integration | What it is |
|---|---|
| [ISPConfig Connect for WHMCS](https://github.com/wadejbeckett/ispconfig-connect-whmcs) | WHMCS provisioning module. Detects this project at runtime with one `get_function_list` call and shows its SSO buttons only when it is installed *and* granted; falls back to displaying the panel URL and username otherwise. |

Nothing on that list is required, and nothing about it is privileged — it is a list of consumers, not
of dependencies. **Built something?** Open a pull request adding a row: name, one sentence, link. A
row needs no approval beyond being real and working.

## Licence

GPLv3 — see [LICENSE](LICENSE). Security reports go to security@noiz.co.za; see
[SECURITY.md](SECURITY.md). Contributions welcome: [CONTRIBUTING.md](CONTRIBUTING.md).
