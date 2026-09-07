# Entra SSO for WordPress

OpenID Connect single sign-on for WordPress with **Microsoft Entra ID**: MFA-aware login, automatic user provisioning, and **security-group → WordPress-role mapping** that re-syncs on every login.

No Composer dependencies — a deliberate choice for enterprise WordPress environments where the dependency footprint must be auditable.

## The flow this implements (matches the screening-question recording)

```
Browser                  WordPress                     Microsoft Entra ID
   │  1. click "Sign in"     │                               │
   │ ───────────────────────▶│                               │
   │                         │  2. 302 /authorize            │
   │ ◀───────────────────────┤  (state + nonce + PKCE)       │
   │  3. login + MFA ─────────────────────────────────────▶│
   │ ◀──────────────────────────────────── code + state ───┤
   │ ───────────────────────▶│  4. validate state (single-use,
   │                         │     TTL 5 min), exchange code │
   │                         │ ─────────────────────────────▶│
   │                         │ ◀──────────── id_token ────────┤
   │                         │  5. validate iss/aud/exp/nonce
   │                         │  6. provision/find user, map
   │                         │     security groups → roles
   │ ◀── logged in, role OK ──┤
```

## Security design decisions

| Threat | Mitigation |
|---|---|
| CSRF on the callback | `state` parameter, single-use transient consumed on first read, 5-minute TTL |
| Token replay | Nonce claim validated with `hash_equals` against the state-bound nonce |
| Code interception | PKCE (`S256`) on the authorization request |
| Secret leakage from DB | Client secret encrypted **AES-256-GCM**; key injected from Azure Key Vault via env constant |
| Open redirect | `wp_safe_redirect()` only; no client-controlled redirect targets |
| Privilege creep | Roles re-mapped from security groups on **every** login; stale roles removed |
| Unauthorized accounts | Optional `allowed_groups` gate — login refused unless user is in a permitted group |
| Password attacks | Optional SSO-only mode disables password authentication entirely |

## Group → role mapping

Configured in **Settings → Entra SSO** as Entra **group Object IDs → WordPress roles**:

| Entra security group | WP role |
|---|---|
| `HR-Portal-Admins` object ID | `editor` |
| `Intranet-Authors` object ID | `author` |
| `All-Staff` object ID | `subscriber` (default) |

On each login the plugin reads the `groups` claim, resolves every matching role, and **replaces** the user's roles — so directory changes take effect on next login with no cron job needed.

## Entra ID app registration (setup guide)

1. **Entra admin center → App registrations → New registration**
2. Name: `Intranet WordPress SSO`; supported accounts: *Accounts in this organizational directory only*
3. **Redirect URI (Web):** `https://intranet.example.com/wp-login.php?action=entra_sso_callback`
4. **Certificates & secrets → New client secret** → copy the value
5. **API permissions:** `openid`, `profile`, `email`, `User.Read` (delegated) — grant admin consent
6. **Token configuration → Add groups claim:** Security groups → *Group ID* (puts group Object IDs into the `groups` claim; for users in 200+ groups, switch to the `hasgroups` + Graph fallback pattern)
7. Paste Tenant ID, Client ID and secret into the plugin settings page

## Demo recording script (for the screening answer)

1. Show the settings page briefly (tenant/app IDs, group mapping — no secret visible)
2. Open a logged-out incognito window → `wp-login.php` → click **Sign in with Microsoft**
3. Show the redirect to `login.microsoftonline.com` (address bar visible) → enter test account → MFA prompt
4. Land back in WordPress admin → open **Users** → highlight the provisioned user + assigned role
5. In the Entra admin center, remove the user from the mapped group → log in again → role reverted (proves live group→role sync)

## Files

```
wp-entra-sso.php                  Plugin bootstrap
includes/class-options.php        Encrypted settings (AES-256-GCM, Key Vault-ready)
includes/class-oidc-client.php    PKCE auth URL, token exchange, ID-token validation
includes/class-provisioning.php   User provisioning + security-group→role mapping
includes/class-login-flow.php     Login button, single-use state callback, redirects
includes/class-settings-page.php  Admin UI
```
