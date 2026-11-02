output "pages_project_name" {
  value = cloudflare_pages_project.blueteamzone-com.name
}

output "pages_default_domain" {
  value = "${cloudflare_pages_project.blueteamzone-com.name}.pages.dev"
}

output "custom_domain" {
  value = var.domain
}
