resource "cloudflare_ruleset" "www_redirect" {
  zone_id     = data.cloudflare_zone.this.id
  name        = "www-to-apex-redirect"
  description = "301 redirect www to the apex domain"
  kind        = "zone"
  phase       = "http_request_dynamic_redirect"

  rules = [
    {
      action      = "redirect"
      expression  = "(http.host eq \"www.${var.domain}\")"
      description = "www to apex"
      enabled     = true
      action_parameters = {
        from_value = {
          status_code           = 301
          preserve_query_string = true
          target_url = {
            expression = "concat(\"https://${var.domain}\", http.request.uri.path)"
          }
        }
      }
    }
  ]
}
