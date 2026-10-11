terraform {
  required_version = ">= 1.10.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.27.0"
    }
  }

  backend "s3" {
    bucket                      = "blueteamzone-bucket"
    key                         = "terraform.tfstate"
    region                      = "auto"
    endpoints                   = { s3 = "https://75fb02c872fe7c70cf127b5d17f97e51.r2.cloudflarestorage.com" }
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_metadata_api_check     = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
    use_lockfile                = true
  }
}
