# cloudflare_zone_settings_override is not used here: on Free-plan zones
# the provider tries to touch plan-gated settings (e.g. image_resizing)
# regardless of what's declared, and the apply fails on those. These are
# set manually via dashboard instead:
#   SSL: Full (strict) · Always Use HTTPS: on · Min TLS: 1.3
#   Automatic HTTPS Rewrites: on · Browser Integrity Check: on
#   Security Level: medium · Bot Fight Mode: on
