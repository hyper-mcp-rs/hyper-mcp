terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

provider "google" {
  project = var.project_id
}

resource "google_service_account" "my-app" {
  account_id = "${var.name}-my-app"
}

# Create a secret for the config file
resource "google_secret_manager_secret" "hyper-mcp-config" {
  secret_id = "${var.name}-config"

  replication {
    auto {}
  }
}

# Add the config file content to the secret
resource "google_secret_manager_secret_version" "hyper-mcp-config-version" {
  secret      = google_secret_manager_secret.hyper-mcp-config.id
  secret_data = <<EOF
{
  "plugins": [
    {
      "name": "time",
      "path": "oci://ghcr.io/hyper-mcp-rs/time-plugin:latest"
    },
    {
      "name": "qr-code",
      "path": "oci://ghcr.io/hyper-mcp-rs/qrcode-plugin:latest"
    },
    {
      "name": "meme-generator",
      "path": "oci://ghcr.io/hyper-mcp-rs/meme-generator-plugin:latest"
    }
  ]
}
EOF
}

# Grant the service account access to the secret
resource "google_secret_manager_secret_iam_member" "secret-access" {
  secret_id = google_secret_manager_secret.hyper-mcp-config.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.my-app.email}"
}

resource "google_cloud_run_service" "my-app" {
  name     = var.name
  location = var.region

  template {
    spec {
      service_account_name = google_service_account.my-app.email
      containers {
        image = "hyper-mcp-rs/hyper-mcp:nightly"
        args  = ["--transport", "streamable-http", "--bind-address", "0.0.0.0:3001", "--config-file", "/app/config.json"]
        resources {
          limits = {
            memory = "1Gi"
            cpu    = "1"
          }
        }
        env {
          name  = "NAME"
          value = "fooooo"
        }
        ports {
          name           = "http1"
          container_port = 3001
        }
        volume_mounts {
          name       = "config"
          mount_path = "/app"
        }
      }
      volumes {
        name = "config"
        secret {
          secret_name = google_secret_manager_secret.hyper-mcp-config.secret_id
          items {
            key  = "latest"
            path = "config.json"
          }
        }
      }
    }
  }
}

# noauth invoker
data "google_iam_policy" "noauth" {
  binding {
    role = "roles/run.invoker"
    members = [
      "allUsers",
    ]
  }
}

resource "google_cloud_run_service_iam_policy" "noauth" {
  location    = var.region
  service     = google_cloud_run_service.my-app.name
  policy_data = data.google_iam_policy.noauth.policy_data
}
