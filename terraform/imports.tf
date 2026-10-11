import {
  to = cloudflare_pages_project.portfolio
  id = "${var.cloudflare_account_id}/blueteamzone-com"
}

import {
  to = cloudflare_pages_domain.custom_domain
  id = "${var.cloudflare_account_id}/blueteamzone-com/${var.domain}"
}

import {
  to = cloudflare_dns_record.www
  id = "455a56a63b356d50fd4005faab66f60d/14bc33fa8e6fdf41cd5aac77898bf436"
}

import {
  to = cloudflare_ruleset.waf_custom
  id = "zones/455a56a63b356d50fd4005faab66f60d/fe75b9c68eb040929b25667522eba4c6"
}

import {
  to = cloudflare_ruleset.www_redirect
  id = "zones/455a56a63b356d50fd4005faab66f60d/3c3fc6e636d3461795454c152f781aa5"
}

import {
  to = cloudflare_ruleset.rate_limit
  id = "zones/455a56a63b356d50fd4005faab66f60d/d1a9d179af274a3fb44d97f93ea5bea8"
}