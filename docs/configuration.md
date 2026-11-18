# Configuration Reference

Orator Authentication accepts configuration through two mechanisms:

1. **Constructor Options** - Passed when instantiating the service provider (highest priority)
2. **Fable Settings** - Read from `fable.settings` with `OratorAuthentication*` prefix

Constructor options take precedence over Fable settings.

## Core Settings

| Option | Fable Setting | Default | Description |
|--------|---------------|---------|-------------|
| `RoutePrefix` | `OratorAuthenticationRoutePrefix` | `'/1.0/'` | URL prefix for all authentication routes |
| `CookieName` | `OratorAuthenticationCookieName` | `'SessionID'` | Name of the session cookie |
| `SessionTTL` | `OratorAuthenticationSessionTTL` | `86400000` (24h) | Session time-to-live in milliseconds |
| `CookiePath` | -- | `'/'` | Path scope for the session cookie |
| `CookieHttpOnly` | -- | `true` | Set HttpOnly flag on cookie |
| `CookieSecure` | -- | `false` | Set Secure flag on cookie (HTTPS only) |
| `CookieSameSite` | `OratorAuthenticationCookieSameSite` | `'Lax'` | SameSite attribute on the session cookie: `'Lax'`, `'Strict'`, `'None'` (needs `CookieSecure: true`), or `false` to leave it off. See [SameSite](#samesite) |
| `AllowCrossSiteDeauthenticate` | `OratorAuthenticationAllowCrossSiteDeauthenticate` | `false` | Let `Deauthenticate` sign the user out on a request the browser marks as cross-site. Off by default, so such a request gets a `403`. Only `true`, `'true'` or `'1'` turn it on; `'false'` and any other value leave it off. See [Cross-site sign-out](#cross-site-sign-out) |
| `DeniedPasswords` | `OratorAuthenticationDeniedPasswords` | `[]` | Array of passwords to reject immediately |

## SameSite

The session cookie carries `SameSite=Lax` unless you configure otherwise. It is the last attribute, after `Secure`:

```
SessionID=f47ac10b-58cc-4372-a567-0e02b2c3d479; Path=/; HttpOnly; SameSite=Lax
```

The clearing cookie that `Deauthenticate` sends is built by the same code. It has the same `Path`, which, with the cookie name, is what the browser matches on to remove the session cookie. It also has the same `Secure` and `SameSite` attributes, so a browser never rejects the clearing cookie when it accepted the session cookie. `SameSite` is not part of that match, so a session cookie set by an earlier version (with no `SameSite`) is still removed.

### Values

- **`'Lax'` (default)** - The cookie is sent on same-site requests and on top-level `GET` links from other sites. A cross-site form `POST` does not carry the session, in any browser. Neither do cross-site `fetch`, iframe or image requests.
- **`'Strict'`** - The cookie is also left off the navigation request when the user arrives from another site, for example by a link in an email or the redirect back from an OAuth provider. Anything decided on that first request, such as a server-rendered page or a server-side redirect to a login page, sees no session. Requests the page makes afterwards (`fetch`/XHR, such as a `CheckSession` call) and clicks within the app do carry the cookie, so an app that checks the session after the page loads is not affected. Do not count on a refresh to bring the cookie back: Firefox treats a reload of that page as cross-site too.
- **`'None'`** - Lets the browser send the cookie in cross-site contexts, such as the app running in an iframe on another site. Use it only when the app has to work embedded in another site, and note that it also gives up the cross-site `POST` protection that `Lax` gives. `None` is needed for embeds but does not guarantee the cookie is sent there: Safari blocks third-party cookies, Firefox keeps them separate for each top-level site (so a sign-in made in a normal tab is not seen inside the embed), and Chrome blocks them when the user has turned that on, as Incognito does by default. It requires `CookieSecure: true`: browsers reject `SameSite=None` without `Secure`, which would drop the cookie and log everyone out. Without `CookieSecure: true` the setting falls back to `Lax` and logs a warning.
- **`false`** - The attribute is left off (the header from earlier versions). Each browser then applies its own default.

Values are case-insensitive (`'strict'` works). `null` and `undefined` mean the default (`Lax`), so a host that passes through an unset setting keeps the protection. Any other value (an empty string, `true`, a number, a misspelling) logs a warning and uses `Lax`.

```javascript
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication',
	{
		CookieSecure: true,
		CookieSameSite: 'Strict'
	});
```

### Why Lax is the default

Without a SameSite attribute, a page on another site can submit a form that POSTs to your API, and the browser attaches the signed-in user's session cookie. Firefox and Safari always do this. Chrome treats a cookie with no attribute as Lax, but still sends it on cross-site POSTs for the first two minutes after it is set. With `SameSite=Lax`, no browser sends the cookie on those requests.

### What Lax does not stop

- **Cross-site top-level `GET` navigations still carry the cookie.** A link or redirect from another site to a `GET` route arrives signed in, so state-changing `GET` routes are not protected by SameSite. That includes `GET /1.0/Authenticate/:username/:password`. Keep your own state-changing routes off `GET`.
- **Lax alone would not stop another site from signing the user out.** A cross-site `GET` link to `/1.0/Deauthenticate` carries the cookie. A cross-site `POST` does not, but the clearing cookie needs no incoming cookie, and the browser stores a cookie set in the response to a top-level navigation whatever its `SameSite` value. `Strict` does not change this. `Deauthenticate` therefore has its own check; see [Cross-site sign-out](#cross-site-sign-out). That check covers `Deauthenticate` only, and login CSRF (next item) is another way to sign the user out.
- **Login CSRF is not prevented.** Another site can still sign the browser in to an account the attacker controls, for example with a link to `GET /1.0/Authenticate/:username/:password` or a form POST to `/1.0/Authenticate`. With the default authenticator, which accepts any credentials, no real account is needed. The browser stores a cookie set in the response to a top-level navigation, so the new session cookie replaces the user's own: the user is signed out of their account (their server-side session stays until it expires) and signed in as someone else. The OAuth callback can be used the same way, because the OAuth state is kept on the server and is not tied to the browser that started the sign-in.
- **SameSite works on sites, not origins.** Other subdomains of the same domain (`other.example.com` and `app.example.com`) count as same-site.

SameSite is defense in depth. A route that changes state and must be safe from other sites should still check something a cross-site page cannot send, such as a custom request header or a CSRF token.

## Cross-site sign-out

`GET` and `POST /1.0/Deauthenticate` refuse a request that the browser marks as coming from another site. The response is a `403`:

```json
{
	"LoggedIn": true,
	"Error": "Cross-site sign-out refused."
}
```

`LoggedIn` says whether the request carried a valid session. No session is destroyed and no cookie is sent, so the user stays signed in. One line is logged at info level, naming the header that decided (`Sec-Fetch-Site` or `Origin`); it does not include the session ID or any header values.

How the request is judged:

1. **`Sec-Fetch-Site`**, which current browsers send on every request to an `https://` site or to `localhost`, decides on its own when present. `cross-site` (in any case) is refused. `same-origin`, `same-site` and `none` are allowed. Browsers send `none` for a navigation they start themselves: a typed address, a bookmark, or a link opened from another application, such as a desktop mail or chat app or a PDF viewer.
2. **No `Origin` header** (and no `Sec-Fetch-Site`) is allowed. This covers the CLI, `curl`, server-to-server calls and other clients that are not browsers.
3. **Otherwise the `Origin` header** must name this server. Its host name must match the `Host` header or the first value of `X-Forwarded-Host` (set by a reverse proxy). Case and a trailing dot are ignored. If that header includes a port, the Origin's port must match too, and `:443` for `https` or `:80` for `http` counts as no port. If the header has no port, only the host names are compared, because many reverse proxies drop the port (nginx's `proxy_set_header Host $host` does). `Origin: null`, a value that is not an `http` or `https` URL, or no match is refused.

A proxy that replaces the `Host` header with its own upstream name (for example `localhost:3000`) has to pass the browser's host on in `X-Forwarded-Host`, or same-origin sign-outs from browsers that do not send `Sec-Fetch-Site` are refused. For nginx: `proxy_set_header X-Forwarded-Host $http_host;`.

The two rules treat other subdomains differently. With `Sec-Fetch-Site`, `same-site` is allowed, so a page on another subdomain of the same site (`other.example.com` for `app.example.com`) can sign the user out; `SameSite` treats those subdomains as one site too. Under the `Origin` rule (plain `http://` sites, or browsers that do not send `Sec-Fetch-Site`), only this server's own host name matches, so the same request is refused. A page on another port of the same host is allowed by both rules when the `Host` header has no port.

The check does not stop every forced sign-out:

- **Requests with neither header.** A cross-site `GET` that arrives with no `Sec-Fetch-Site` and no `Origin` looks like a request from a non-browser client and is allowed, because browsers do not send `Origin` on a `GET` navigation. That happens in browsers too old to send `Sec-Fetch-Site`, and on sites served over plain `http://` (other than `localhost`), where browsers do not send it. A cross-site `POST` still carries `Origin` in both cases and is refused. Serve the app over HTTPS to close the second gap.
- **Links opened from outside the browser.** A sign-out link sent by email or chat and opened from a desktop app arrives with `Sec-Fetch-Site: none` and the session cookie, and is allowed. A link clicked in webmail running in the browser is `cross-site` and refused.
- **Login CSRF.** Another site can replace the session cookie by signing the browser in to a different account, which signs the user out of their own. See [What Lax does not stop](#what-lax-does-not-stop).

If a page on another site has to be able to sign users out, for example a sign-out link in another app on a different domain, set `AllowCrossSiteDeauthenticate: true` (or the `OratorAuthenticationAllowCrossSiteDeauthenticate` fable setting). That turns the check off for every site, which brings back the forced sign-out described above. Only `true`, `'true'` or `'1'` (any case) turn it on. Any other value, including the text `'false'` that `${ENV|false}` settings templating produces, leaves the check on, and a value that is not recognized as on or off also logs a warning.

```javascript
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication',
	{
		AllowCrossSiteDeauthenticate: true
	});
```

The check applies only to `Deauthenticate`. `Authenticate`, `CheckSession` and the OAuth routes are not affected; the OAuth callback is a cross-site navigation from the provider by design. `Session/Context` accepts only `POST`, so with `Lax` or `Strict` the session cookie is not sent on a cross-site request there.

## OAuth Settings

| Option | Fable Setting | Default | Description |
|--------|---------------|---------|-------------|
| `OAuthStateTTL` | `OratorAuthenticationOAuthStateTTL` | `300000` (5m) | OAuth state parameter TTL in milliseconds |
| `OAuthPostLoginRedirectURL` | `OratorAuthenticationOAuthPostLoginRedirectURL` | `'/'` | URL to redirect to after successful OAuth login |
| `OAuthProviders` | -- | `{}` | Map of provider name -> provider configuration |

## OAuth Provider Configuration

Each entry in `OAuthProviders` is keyed by a provider name and contains:

### OpenID Connect Provider (`Type: 'openid-connect'`)

| Field | Required | Description |
|-------|----------|-------------|
| `Type` | Yes | Must be `'openid-connect'` |
| `IssuerURL` | Yes | OIDC issuer URL (e.g., `'https://accounts.google.com'`) |
| `ClientID` | Yes | OAuth client ID from the provider's developer console |
| `ClientSecret` | Yes | OAuth client secret |
| `CallbackURL` | Yes | Full callback URL registered with the provider |
| `Scopes` | No | Array of scopes (default: `['openid', 'profile', 'email']`) |

### MSAL Provider (`Type: 'msal'`)

| Field | Required | Description |
|-------|----------|-------------|
| `Type` | Yes | Must be `'msal'` |
| `ClientID` | Yes | Azure AD application (client) ID |
| `ClientSecret` | Yes | Azure AD client secret |
| `Authority` | No | Authority URL (default: `'https://login.microsoftonline.com/common'`) |
| `TenantID` | No | Azure AD tenant ID (used if `Authority` is not set) |
| `CallbackURL` | Yes | Full callback URL registered in Azure portal |
| `Scopes` | No | Array of scopes (default: `['openid', 'profile', 'email']`) |

## Example Configurations

### Minimal (Development)

```javascript
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication');
```

Uses all defaults: allow-all authenticator, 24-hour sessions, no OAuth.

### Production Username/Password

```javascript
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication',
	{
		SessionTTL: 7200000,       // 2 hours
		CookieSecure: true,        // HTTPS only
		DeniedPasswords: ['password', '123456', 'abc123']
	});
```

### With OAuth Providers

```javascript
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication',
	{
		SessionTTL: 28800000,      // 8 hours
		CookieSecure: true,
		OAuthPostLoginRedirectURL: '/dashboard',
		OAuthProviders:
		{
			'google':
			{
				Type: 'openid-connect',
				IssuerURL: 'https://accounts.google.com',
				ClientID: 'your-google-client-id.apps.googleusercontent.com',
				ClientSecret: 'your-google-client-secret',
				CallbackURL: 'https://myapp.com/1.0/OAuth/Callback/google',
				Scopes: ['openid', 'profile', 'email']
			},
			'microsoft':
			{
				Type: 'msal',
				ClientID: 'your-azure-client-id',
				ClientSecret: 'your-azure-client-secret',
				Authority: 'https://login.microsoftonline.com/your-tenant-id',
				CallbackURL: 'https://myapp.com/1.0/OAuth/Callback/microsoft',
				Scopes: ['openid', 'profile', 'email', 'Mail.Read']
			}
		}
	});
```

### Via Fable Settings

```javascript
let tmpFable = new libFable(
	{
		Product: 'MyApp',
		ProductVersion: '1.0.0',
		APIServerPort: 8080,

		OratorAuthenticationRoutePrefix: '/api/v2/',
		OratorAuthenticationSessionTTL: 3600000,
		OratorAuthenticationCookieName: 'AppSession'
	});

// No options needed -- reads from Fable settings
tmpFable.serviceManager.instantiateServiceProvider('OratorAuthentication');
```
