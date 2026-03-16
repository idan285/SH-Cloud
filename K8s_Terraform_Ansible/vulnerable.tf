# -----------------------------------------------------------------------
# VULNERABLE TERRAFORM EXAMPLE — FOR CHECKMARX ONE KICS DEMO ONLY
# This file contains intentional misconfigurations for training purposes.
# DO NOT use in any real environment.
# -----------------------------------------------------------------------

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = "my-demo-project"
  region  = "us-central1"
}

# -----------------------------------------------------------------------
# VULNERABILITY: GCS bucket with public access granted to allUsers.
# Anyone on the internet can read all objects in this bucket.
# KICS Rule: "Google Storage Bucket Is Publicly Accessible"
# -----------------------------------------------------------------------
resource "google_storage_bucket" "insecure_bucket" {
  name          = "my-demo-insecure-bucket"
  location      = "US"
  force_destroy = true

  # VULNERABILITY: uniform bucket-level access is disabled,
  # allowing per-object ACLs which are harder to audit and control.
  uniform_bucket_level_access = false
}

# VULNERABILITY: grants read access to ALL users on the internet.
resource "google_storage_bucket_iam_binding" "public_read" {
  bucket = google_storage_bucket.insecure_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}

# -----------------------------------------------------------------------
# VULNERABILITY: Compute instance with a public IP and overly broad
# service account scope (full cloud-platform access).
# KICS Rules:
#   "Google Compute Instance Has Public IP"
#   "Google Compute Instance With Attached Default Service Account"
# -----------------------------------------------------------------------
resource "google_compute_instance" "insecure_vm" {
  name         = "insecure-demo-vm"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"

      # VULNERABILITY: boot disk is not encrypted with a customer-managed key.
      # Default Google-managed encryption is used — no customer control.
    }
  }

  network_interface {
    network = "default"

    # VULNERABILITY: access_config block assigns a public (ephemeral) IP
    # to this instance, exposing it directly to the internet.
    access_config {}
  }

  # VULNERABILITY: using full cloud-platform scope grants this VM
  # access to ALL GCP APIs. Should be scoped to only what is needed.
  service_account {
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  # VULNERABILITY: serial port access is enabled, which can expose
  # console output and allow interactive access for debugging —
  # a risk in production environments.
  metadata = {
    serial-port-enable = "true"
  }
}
