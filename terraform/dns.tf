

resource "cloudflare_dns_record" "root" {
  zone_id = data.cloudflare_zone.this.id
  name    = "@"
  type    = "CNAME"
  content = "${var.pages_dev_subdomain}.pages.dev"
  proxied = true
  ttl     = 1

  depends_on = [cloudflare_pages_domain.custom_domain]
}

moved {
  from = cloudflare_record.root
  to   = cloudflare_dns_record.root
}

resource "cloudflare_dns_record" "www" {
  zone_id = data.cloudflare_zone.this.id
  name    = "www"
  type    = "CNAME"
  content = "${var.pages_dev_subdomain}.pages.dev"
  proxied = true
  ttl     = 1
}

moved {
  from = cloudflare_record.www
  to   = cloudflare_dns_record.www
}
