# domain already registered + added as a zone manually
data "cloudflare_zone" "this" {
  filter = {
    name = var.domain
  }
}

resource "cloudflare_zone_dnssec" "this" {
  zone_id = data.cloudflare_zone.this.zone_id

  status = "active"
}