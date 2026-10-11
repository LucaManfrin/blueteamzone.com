resource "cloudflare_ruleset" "waf_custom" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "portfolio-waf-baseline"
  description = "Baseline WAF rules for the portfolio site"
  kind        = "zone"
  phase       = "http_request_firewall_custom"


  # rate-based protection lives in rate_limit.tf (cloudflare_ruleset, http_ratelimit phase)
  rules = [
    {
      action      = "block"
      expression  = "(cf.threat_score gt 30)"
      description = "Block requests from IPs with an elevated Cloudflare threat score"
      enabled     = true
    }
  ]
}
