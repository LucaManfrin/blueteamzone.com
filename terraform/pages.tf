resource "cloudflare_pages_project" "blueteamzone-com" {
  account_id        = var.cloudflare_account_id
  name              = "blueteamzone-com"
  production_branch = "main"

  build_config = {
    build_command   = "npm run build"
    destination_dir = "dist"
    root_dir        = ""
  }

  deployment_configs = {
    preview = {
      env_vars = {
        NODE_VERSION = {
          type  = "plain_text"
          value = "24"
        }
      }
      fail_open = false
    }
    production = {
      env_vars = {
        NODE_VERSION = {
          type  = "plain_text"
          value = "24"
        }
      }
      fail_open = false
    }
  }
}

resource "cloudflare_pages_domain" "custom_domain" {
  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.portfolio.name
  name         = var.domain
}

# www is not registered as a Pages custom domain: it never actually
# serves content, it's redirected to the apex at the edge (see redirect.tf)
# before the request would reach Pages. One less custom domain to verify.
