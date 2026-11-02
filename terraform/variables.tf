variable "domain" {
  description = "The apex domain for the portfolio (e.g. blueteamzone.com)"
  type        = string
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID (found in the dashboard sidebar)"
  type        = string
  sensitive   = true
}

variable "pages_dev_subdomain" {
  description = "The actual <x>.pages.dev subdomain Cloudflare assigned to the project (without .pages.dev). Can differ from the project name if that name was already taken globally — check Workers & Pages > project > Custom domains in the dashboard for the real value."
  type        = string
}
