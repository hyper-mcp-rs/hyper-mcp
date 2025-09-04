Deployment
==========

## Docker

Assume you have Docker installed.

Pull the image

```sh
docker pull ghcr.io/tuananh/hyper-mcp:latest
```

Create a sample config file like this, assume at `/home/ubuntu/config.json`

```json
{
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "qr_code": {
      "url": "oci://ghcr.io/tuananh/qrcode-plugin:latest"
    }
  }
}
```

> 📖 **For authentication configuration and advanced options, see [RUNTIME_CONFIG.md](./RUNTIME_CONFIG.md)**

### Authentication in Docker

For production deployments with authentication, you have several options:

**Option 1: Mount keyring (Linux only)**
```sh
docker run -d \
    --name hyper-mcp \
    -p 3001:3001 \
    -v /home/ubuntu/config.json:/app/config.json \
    -v ~/.local/share/keyrings:/home/appuser/.local/share/keyrings:ro \
    ghcr.io/tuananh/hyper-mcp \
    --transport sse \
    --bind-address 0.0.0.0:3001 \
    --config-file /app/config.json
```

**Option 2: Use Docker secrets**
```sh
# Create secrets
echo '{"type":"basic","username":"user","password":"pass"}' | docker secret create registry_auth -

# Run with secrets
docker run -d \
    --name hyper-mcp \
    -p 3001:3001 \
    -v /home/ubuntu/config.json:/app/config.json \
    --secret registry_auth \
    ghcr.io/tuananh/hyper-mcp \
    --transport sse \
    --bind-address 0.0.0.0:3001 \
    --config-file /app/config.json
```

**Option 3: Environment-based credentials**
```sh
docker run -d \
    --name hyper-mcp \
    -p 3001:3001 \
    -v /home/ubuntu/config.json:/app/config.json \
    -e REGISTRY_USER="username" \
    -e REGISTRY_PASS="password" \
    ghcr.io/tuananh/hyper-mcp \
    --transport sse \
    --bind-address 0.0.0.0:3001 \
    --config-file /app/config.json
```

Run the container

```sh
docker run -d \
    --name hyper-mcp \
    -p 3001:3001 \
    -v /home/ubuntu/config.json:/app/config.json \
    ghcr.io/tuananh/hyper-mcp \
    --transport sse \
    --bind-address 0.0.0.0:3001 \
    --config-file /app/config.json
```

Note that we need to bind to `--bind-address 0.0.0.0:3001` in order to access from the host.

## GCP Cloud Run

### Prerequisites
- Google Cloud SDK installed
- Terraform installed
- A GCP project with Cloud Run and Secret Manager APIs enabled

### Configuration

1. Create a `terraform.tfvars` file with your configuration in `iac` folder:

```hcl
name       = "hyper-mcp"
project_id = "your-project-id"
region     = "asia-southeast1"  # or your preferred region
```

2. Create a config file in Secret Manager:

The config file will be automatically created and managed by Terraform. Here's an example of what it contains:

```json
{
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "qr_code": {
      "url": "oci://ghcr.io/tuananh/qrcode-plugin:latest"
    }
  }
}
```

For production deployments with authentication, update the config to use Secret Manager:

```json
{
  "auths": {
    "https://private.registry.example.com": {
      "type": "basic",
      "username": "registry-user",
      "password": "registry-password"
    }
  },
  "plugins": {
    "time": {
      "url": "oci://ghcr.io/tuananh/time-plugin:latest"
    },
    "private_plugin": {
      "url": "https://private.registry.example.com/secure-plugin:latest",
      "runtime_config": {
        "allowed_hosts": ["private.registry.example.com"]
      }
    }
  }
}
```

3. Deploy using Terraform:

```sh
cd iac
terraform init
terraform plan
terraform apply
```

The service will be deployed with:
- Port 3001 exposed
- Config file mounted at `/app/config.json`
- Public access enabled
- SSE transport mode
- Bound to 0.0.0.0:3001

### Accessing the Service

After deployment, you can get the service URL using:

```sh
terraform output url
```

The service will be accessible at the provided URL.

### Authentication with GCP Secret Manager

For secure credential management in GCP Cloud Run:

1. Store authentication credentials in Secret Manager:
```sh
# Store registry credentials
gcloud secrets create registry-auth --data-file=- <<< '{"type":"basic","username":"user","password":"pass"}'

# Store API tokens  
gcloud secrets create api-token --data-file=- <<< '{"type":"token","token":"your-api-token"}'
```

2. Update your Terraform configuration to mount secrets:
```hcl
resource "google_cloud_run_service" "hyper_mcp" {
  # ... existing configuration ...
  
  template {
    spec {
      containers {
        # ... existing container config ...
        
        env {
          name = "CONFIG_FILE"
          value = "/app/config.json"
        }
        
        volume_mounts {
          name       = "secrets"
          mount_path = "/app/secrets"
        }
      }
      
      volumes {
        name = "secrets"
        secret {
          secret_name = google_secret_manager_secret.registry_auth.secret_id
        }
      }
    }
  }
}
```

## Production Security Considerations

### Authentication Best Practices
- **Never include credentials in Docker images or version control**
- **Use keyring authentication for local development** 
- **Use cloud-native secret management for production** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- **Rotate credentials regularly and update keyring/secret stores**
- **Use least-privilege access principles** for service accounts
- **Monitor authentication failures** in logs

### Container Security
- **Run containers with non-root users**
- **Use read-only filesystems where possible**
- **Limit container network access**
- **Scan images for vulnerabilities regularly**
- **Use distroless or minimal base images**

## Cloudflare Workers

Not possible yet but it's in my TODO list.