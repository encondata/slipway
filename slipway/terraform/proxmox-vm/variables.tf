# Every variable here is a key of the terraform.tfvars.json Slipway writes
# (terraform.tfvars in slipway/services/terraform.py), and nothing else is. The checks repeat
# Slipway's own (slipway/services/vmnet.py, §5 of the phase 5 design) so a value Slipway
# should never write stops at plan time rather than reaching Proxmox.
#
# The API token is not a variable: the provider reads it from PROXMOX_VE_API_TOKEN.

variable "endpoint" {
  description = "Proxmox API URL, such as https://pve.example.lan:8006/."
  type        = string
  validation {
    condition     = can(regex("^https://[^/\\s]+(/.*)?$", var.endpoint))
    error_message = "endpoint must be an https:// URL."
  }
}

variable "node" {
  description = "The node the VM is cloned on and lives on."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", var.node))
    error_message = "node must be a Proxmox node name."
  }
}

variable "vm_id" {
  description = "The VM id Slipway reserved before this run."
  type        = number
  validation {
    condition     = var.vm_id >= 100 && var.vm_id <= 999999999 && floor(var.vm_id) == var.vm_id
    error_message = "vm_id must be a whole number from 100 to 999999999."
  }
}

variable "name" {
  description = "The VM's name and guest host name: slipway-<env>-<slot>."
  type        = string
  validation {
    condition     = can(regex("^slipway-[a-z][a-z0-9-]{0,24}[a-z0-9]-(blue|green|data)$", var.name))
    error_message = "name must be slipway-<environment>-<slot>."
  }
}

variable "pool" {
  description = "The resource pool the VM is put in (the token's rights are on it)."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", var.pool))
    error_message = "pool must be a Proxmox pool name."
  }
}

variable "tags" {
  description = "Slipway's markers, sorted as Proxmox stores them: env-<environment id> and slipway."
  type        = list(string)
  validation {
    condition     = contains(var.tags, "slipway") && alltrue([for t in var.tags : can(regex("^[a-z0-9_][a-z0-9_+.-]{0,63}$", t))])
    error_message = "tags must include slipway and hold only Proxmox tag names."
  }
}

variable "description" {
  description = "The VM's notes in Proxmox, naming the environment."
  type        = string
  validation {
    condition     = length(var.description) <= 8192
    error_message = "description must be at most 8192 characters."
  }
}

variable "template_vm_id" {
  description = "The template the VM is fully cloned from."
  type        = number
  validation {
    condition     = var.template_vm_id >= 100 && var.template_vm_id <= 999999999 && floor(var.template_vm_id) == var.template_vm_id
    error_message = "template_vm_id must be a whole number from 100 to 999999999."
  }
}

variable "datastore" {
  description = "The storage for the VM's disk and cloud-init drive."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9._-]{0,63}$", var.datastore))
    error_message = "datastore must be a Proxmox storage name."
  }
}

variable "file_format" {
  description = "qcow2 on a file storage (so it can take VM snapshots), raw otherwise."
  type        = string
  validation {
    condition     = contains(["qcow2", "raw"], var.file_format)
    error_message = "file_format must be qcow2 or raw."
  }
}

variable "bridge" {
  description = "The bridge (or SDN VNet) the VM's network card is on."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9._-]{0,15}$", var.bridge))
    error_message = "bridge must be a Proxmox bridge name."
  }
}

variable "vlan_id" {
  description = "The VLAN tag on the bridge, or null for none."
  type        = number
  default     = null
  nullable    = true
  validation {
    condition     = var.vlan_id == null ? true : (var.vlan_id >= 1 && var.vlan_id <= 4094 && floor(var.vlan_id) == var.vlan_id)
    error_message = "vlan_id must be null or a whole number from 1 to 4094."
  }
}

variable "cores" {
  description = "vCPUs."
  type        = number
  validation {
    condition     = var.cores >= 1 && var.cores <= 64 && floor(var.cores) == var.cores
    error_message = "cores must be a whole number from 1 to 64."
  }
}

variable "memory_mb" {
  description = "Memory in MB."
  type        = number
  validation {
    condition     = var.memory_mb >= 2048 && var.memory_mb <= 262144 && floor(var.memory_mb) == var.memory_mb
    error_message = "memory_mb must be a whole number from 2048 to 262144."
  }
}

variable "disk_gb" {
  description = "The boot disk's size in GB. Disks only grow."
  type        = number
  validation {
    condition     = var.disk_gb >= 20 && var.disk_gb <= 4096 && floor(var.disk_gb) == var.disk_gb
    error_message = "disk_gb must be a whole number from 20 to 4096."
  }
}

variable "address_cidr" {
  description = "The VM's static IPv4 address with its prefix, such as 10.0.0.12/24."
  type        = string
  validation {
    condition     = can(cidrhost(var.address_cidr, 0)) && can(regex("^\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+$", var.address_cidr))
    error_message = "address_cidr must be an IPv4 address with a prefix."
  }
}

variable "gateway" {
  description = "The network's IPv4 gateway."
  type        = string
  validation {
    condition     = can(regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$", var.gateway)) && can(cidrhost("${var.gateway}/32", 0))
    error_message = "gateway must be an IPv4 address."
  }
}

variable "dns_servers" {
  description = "1 to 3 IPv4 DNS servers (the gateway when the network names none)."
  type        = list(string)
  validation {
    condition     = length(var.dns_servers) >= 1 && length(var.dns_servers) <= 3 && alltrue([for s in var.dns_servers : can(regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$", s)) && can(cidrhost("${s}/32", 0))])
    error_message = "dns_servers must hold 1 to 3 IPv4 addresses."
  }
}

variable "ssh_public_key" {
  description = "The slipway user's authorized key (the host row's generated client key)."
  type        = string
  validation {
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( .*)?$", var.ssh_public_key))
    error_message = "ssh_public_key must be one OpenSSH public key."
  }
}
