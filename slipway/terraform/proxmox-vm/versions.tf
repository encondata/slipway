# Slipway's bundled root module for one Proxmox VM (docs/machines.md).
#
# Slipway writes only terraform.tfvars.json next to these files; every value it sets is a
# variable in variables.tf. The versions are exact: slipway/services/terraform.py
# (TERRAFORM_VERSION, PROVIDER_VERSION) and the Dockerfile pin the same ones, and the
# provider's checksums are in .terraform.lock.hcl, which `init -lockfile=readonly` enforces.

terraform {
  required_version = "= 1.16.5"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "= 0.115.0"
    }
  }
}
