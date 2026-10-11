resource "cloudflare_ruleset" "rate_limit" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "portfolio-rate-limit"
  description = "Basic protection against scraping / traffic floods"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules = [
    {
      action      = "block"
      expression  = "(http.request.uri.path contains \"/\")"
      description = "Challenge IPs exceeding request threshold"
      enabled     = true
      ratelimit = {
        characteristics     = ["cf.colo.id", "ip.src"]
        period              = 10
        requests_per_period = 20
        mitigation_timeout  = 10
      }
    }
  ]
}
