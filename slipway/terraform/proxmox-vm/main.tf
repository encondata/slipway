# One Proxmox VM, fully cloned from the account's template (Sirdar's resource, as a static
# module). Slipway plans and applies it only for a new or half-made VM and for a resize, and
# refuses any plan that would delete it outside Remove (design M6).

provider "proxmox" {
  endpoint = var.endpoint
  # Terraform's SSL_CERT_FILE trusts only the account's pinned certificate, so the
  # certificate is checked, never skipped.
  insecure = false
  # The API token comes from PROXMOX_VE_API_TOKEN in Terraform's environment only.
}

resource "proxmox_virtual_environment_vm" "vm" {
  node_name   = var.node
  vm_id       = var.vm_id
  name        = var.name
  pool_id     = var.pool
  tags        = var.tags
  description = var.description

  started          = true
  on_boot          = true
  stop_on_destroy  = true
  purge_on_destroy = true
  # Slipway shuts the VM down itself before a resize and starts it again (design D12), so
  # the provider never reboots it on its own.
  reboot_after_update = false
  timeout_clone       = 1800

  scsi_hardware = "virtio-scsi-single"

  clone {
    vm_id        = var.template_vm_id
    node_name    = var.node
    datastore_id = var.datastore
    full         = true
  }

  agent {
    enabled = true
    timeout = "5m"
  }

  cpu {
    cores = var.cores
    type  = "host"
  }

  memory {
    dedicated = var.memory_mb
  }

  disk {
    interface    = "scsi0"
    datastore_id = var.datastore
    size         = var.disk_gb
    file_format  = var.file_format
    discard      = "on"
    iothread     = true
  }

  network_device {
    bridge  = var.bridge
    model   = "virtio"
    vlan_id = var.vlan_id
  }

  # The template's cloud-init drive is ide2 (docs/machines.md). Its first-boot package
  # upgrade (ciupgrade) is left to the template, which should have it off; Slipway's Test
  # warns when it is on.
  initialization {
    interface    = "ide2"
    datastore_id = var.datastore

    # Slipway's Linux user (cloudinit.GUEST_USER). cloud-init's ciuser takes over the Ubuntu
    # image's default user, which keeps its passwordless sudo.
    user_account {
      username = "slipway"
      keys     = [var.ssh_public_key]
    }

    ip_config {
      ipv4 {
        address = var.address_cidr
        gateway = var.gateway
      }
    }

    dns {
      servers = var.dns_servers
    }
  }

  lifecycle {
    # A change of template or clone settings must never replace a made VM.
    ignore_changes = [clone]
  }
}
