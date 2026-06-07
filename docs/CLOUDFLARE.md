# Cloudflare recommended settings

Your DNS is on Cloudflare and deploys go through Netlify. Use Cloudflare as a
secure, cached front door. Set DNS records to **Proxied** (orange cloud) so the
settings below actually apply, and turn off any feature that would rewrite the
HTML Netlify already optimises.

> [!NOTE]
> Netlify already sends HSTS and a strict CSP. Cloudflare should **reinforce**,
> not duplicate or weaken, those. Don't let Cloudflare strip or rewrite headers.

## SSL/TLS

| Setting               | Value             | Why                                                                 |
| --------------------- | ----------------- | ------------------------------------------------------------------- |
| SSL/TLS mode          | **Full (strict)** | Encrypts Cloudflare↔Netlify and validates Netlify's cert. Prevents downgrade/MITM between edge and origin. |
| Always Use HTTPS      | **On**            | Redirects any `http://` request to `https://`. No plaintext.        |
| Minimum TLS Version   | **1.2** (1.3 ok)  | Drops obsolete, attackable TLS 1.0/1.1.                             |
| TLS 1.3               | **On**            | Faster handshakes, modern ciphers.                                 |
| Automatic HTTPS Rewrites | **On**         | Upgrades stray `http` subresources before they break CSP.          |
| HSTS                  | **On**, 6–24 mo, includeSubDomains, **preload** | Forces HTTPS at the browser even before hitting the edge. Matches the Netlify header. Only enable preload once you're sure every subdomain is HTTPS. |

## Speed / optimisation

| Setting          | Value     | Why                                                                          |
| ---------------- | --------- | ---------------------------------------------------------------------------- |
| Brotli           | **On**    | Better text compression than gzip → faster loads, higher Lighthouse.         |
| Auto Minify      | **Off**   | Astro already minifies. Cloudflare minifying built HTML can break hashed assets and (with strict CSP) inline-style handling. Leave it to the build. |
| Early Hints      | **On**    | Lets browsers preconnect/preload sooner. Safe for static sites.              |
| HTTP/2 + HTTP/3  | **On**    | Multiplexing + QUIC for lower latency.                                       |
| Rocket Loader    | **Off**   | It injects/reorders JS, which conflicts with a strict `script-src 'self'` CSP. |

## Security

| Setting                  | Value                  | Why                                                                 |
| ------------------------ | ---------------------- | ------------------------------------------------------------------- |
| Security Level           | **Medium**             | Challenges the most abusive IPs without annoying real readers.      |
| Browser Integrity Check  | **On**                 | Blocks requests with malformed headers / known-bad user agents.     |
| Bot Fight Mode           | **On** (or Super Bot Fight Mode on paid) | Cheap mitigation of automated abuse and scraping. |
| WAF Managed Rules        | **On** (Cloudflare Managed Ruleset) | Generic protection (injection, traversal, etc.). A static site has little attack surface, but it's free defense-in-depth. |
| DDoS Protection          | **On** (automatic)     | Always-on L3/L4/L7 mitigation. No origin to overwhelm anyway, but protects availability + bills. |
| Hotlink Protection       | Optional **On**        | Stops other sites embedding your images and burning bandwidth.      |
| Email Address Obfuscation| **On**                 | Irrelevant here (we expose no emails) but harmless.                 |

## WAF custom rules (optional, recommended)

- **Block obvious probes:** path contains `wp-admin`, `wp-login`, `.env`,
  `.git`, `xmlrpc.php` → Block. None exist on a static Astro site, so blocking
  them is pure noise reduction and zero false-positive risk.
- **Method allow-list:** only `GET`, `HEAD`, `OPTIONS` are ever needed. Challenge
  or block `POST`/`PUT`/`DELETE` — there are no forms or APIs to receive them.

## Caching

| Setting                | Value                              | Why                                                            |
| ---------------------- | ---------------------------------- | -------------------------------------------------------------- |
| Caching Level          | **Standard**                       | Sensible defaults for a static site.                           |
| Browser Cache TTL      | **Respect Existing Headers**       | Honour the precise `Cache-Control` values set in `netlify.toml`. |
| Cache Rule: `/_astro/*`| Cache everything, Edge TTL 1 year  | Fingerprinted assets are immutable — cache hard at the edge.   |
| Cache Rule: `*.html`   | Cache, but **respect origin** / short TTL | New posts must appear quickly; don't pin stale HTML.    |
| Tiered Cache           | **On**                             | Fewer origin fetches, faster global hits.                      |
| Always Online          | Optional **On**                    | Serves a cached copy if Netlify is briefly unreachable.        |

## Page Rules / redirects

- Prefer a single canonical host (e.g. apex `example.com`). Redirect
  `www → apex` (or vice-versa) at Cloudflare **or** Netlify — pick one to avoid
  redirect loops. A matching example is commented in `netlify.toml`.

## After enabling

1. Verify headers survive the edge:
   `curl -sI https://yourdomain | grep -iE 'content-security|strict-transport|x-frame'`.
2. Re-test CSP — make sure Cloudflare features (Rocket Loader, Auto Minify)
   aren't injecting inline scripts that your `script-src 'self'` will block.
3. Run Lighthouse and [securityheaders.com](https://securityheaders.com) against
   the live domain.
