###############################################################################
# XGenGuardian — staging infrastructure (Phase 1 + 2)
#
# Cheapest viable Phase-1 footprint:
#   - 1× small VM running all services via docker-compose
#   - 1× managed Postgres (or co-located in the VM for dev-cheap)
#   - 1× managed Redis (or co-located)
#   - S3-compatible bucket for evidence (R2 / B2 / Spaces / S3)
#   - DNS records: dns.staging.xgenguardian.io, report.staging.xgenguardian.io
#
# Provider is intentionally generic; swap in DigitalOcean / Vultr / Hetzner /
# Fly.io as preferred. Showing DO here as a representative example.
###############################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.30"
    }
  }
}

variable "do_token" {
  type      = string
  sensitive = true
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "cf_zone_id" {
  type = string
}

variable "region" {
  type    = string
  default = "nyc3"
}

provider "digitalocean" {
  token = var.do_token
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# --- VM ---------------------------------------------------------------------
resource "digitalocean_ssh_key" "ops" {
  name       = "xgg-staging-ops"
  public_key = file("~/.ssh/id_ed25519.pub")
}

resource "digitalocean_droplet" "staging" {
  image    = "ubuntu-24-04-x64"
  name     = "xgg-staging-1"
  region   = var.region
  size     = "s-4vcpu-8gb"
  ssh_keys = [digitalocean_ssh_key.ops.id]
  monitoring = true
  tags = ["xgg", "staging"]

  user_data = <<-EOT
    #cloud-config
    package_update: true
    packages: [docker.io, docker-compose-plugin, ufw]
    runcmd:
      - ufw allow 22/tcp
      - ufw allow 443/tcp
      - ufw allow 853/tcp
      - ufw --force enable
      - systemctl enable --now docker
  EOT
}

# --- Managed Postgres + Redis ----------------------------------------------
resource "digitalocean_database_cluster" "pg" {
  name       = "xgg-staging-pg"
  engine     = "pg"
  version    = "16"
  size       = "db-s-1vcpu-1gb"
  region     = var.region
  node_count = 1
}

resource "digitalocean_database_cluster" "redis" {
  name       = "xgg-staging-redis"
  engine     = "redis"
  version    = "7"
  size       = "db-s-1vcpu-1gb"
  region     = var.region
  node_count = 1
}

# --- Evidence bucket (Spaces; S3-compatible) -------------------------------
resource "digitalocean_spaces_bucket" "evidence" {
  name   = "xgg-staging-evidence"
  region = var.region
  acl    = "private"
}

# --- DNS --------------------------------------------------------------------
resource "cloudflare_record" "dns_doh" {
  zone_id = var.cf_zone_id
  name    = "dns.staging"
  type    = "A"
  value   = digitalocean_droplet.staging.ipv4_address
  proxied = false
}

resource "cloudflare_record" "report" {
  zone_id = var.cf_zone_id
  name    = "report.staging"
  type    = "A"
  value   = digitalocean_droplet.staging.ipv4_address
  proxied = true
}

# --- Outputs ----------------------------------------------------------------
output "droplet_ip" {
  value = digitalocean_droplet.staging.ipv4_address
}

output "pg_dsn" {
  value     = digitalocean_database_cluster.pg.uri
  sensitive = true
}

output "redis_uri" {
  value     = digitalocean_database_cluster.redis.uri
  sensitive = true
}

output "evidence_bucket" {
  value = digitalocean_spaces_bucket.evidence.bucket_domain_name
}
