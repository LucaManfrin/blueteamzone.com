# Infrastructure as Code — Cloudflare

Manages DNS, the Pages project, WAF rules, rate limiting and zone
security settings for the site — one resource type per file:

```
versions.tf       terraform block, provider requirements, backend
providers.tf       cloudflare provider
variables.tf
outputs.tf
zone.tf            zone data source
pages.tf           Pages project + custom domain
dns.tf             DNS records
waf.tf             WAF ruleset
rate_limit.tf
redirect.tf        www -> apex redirect
zone_settings.tf   TLS / SSL / security level (manual, see note in file)
```

## Prerequisites

1. Domain registered and added as a zone in Cloudflare.
2. Cloudflare API Token scoped to:
   - `Zone.DNS: Edit`
   - `Zone.Zone Settings: Edit`
   - `Account.Cloudflare Pages: Edit`
   - `Zone.Firewall Services: Edit`
   - `Zone.Single Redirect: Edit`
   - `Zone.Zone: Read`

## Bootstrap: R2 state bucket (one-time)

The bucket has to exist before the first `terraform init`.

```bash
npx wrangler r2 bucket create blueteamzone-com
```

Then create a bucket-scoped R2 API token (dashboard → R2 → Manage R2 API
tokens → Object Read & Write, scoped to this bucket only) — separate
from `CLOUDFLARE_API_TOKEN`.

R2 credentials are passed at init time via partial backend config, never
hardcoded:

```bash
terraform init \
  -backend-config="access_key=$R2_ACCESS_KEY_ID" \
  -backend-config="secret_key=$R2_SECRET_ACCESS_KEY"
```

In CI these come from `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY`
secrets — see `.github/workflows/deploy-infra.yml`.

State locking uses `use_lockfile = true` (Terraform ≥1.11, conditional
write, no DynamoDB needed).

## Local usage

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in real values
export CLOUDFLARE_API_TOKEN="your-token"
export R2_ACCESS_KEY_ID="your-r2-access-key-id"
export R2_SECRET_ACCESS_KEY="your-r2-secret-access-key"

terraform init \
  -backend-config="access_key=$R2_ACCESS_KEY_ID" \
  -backend-config="secret_key=$R2_SECRET_ACCESS_KEY"

terraform plan
terraform apply
```

## Free-plan gotchas hit along the way

- Rate limiting: `period` and `mitigation_timeout` are restricted to `10`
  on Free; `challenge`-type actions aren't available (use `block`).
- `www.pages.dev` project subdomain can differ from the project name if
  that name is already taken globally — check the dashboard.
- Cloudflare Pages needs at least one manual deploy from the dashboard
  before the API will accept Pages calls for a brand-new account.

## CI

`deploy-infra.yml` always runs `plan`; `apply` only triggers (behind
manual approval on the `infra` environment) if the plan actually detected
changes.
