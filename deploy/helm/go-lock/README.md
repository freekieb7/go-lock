# go-lock Helm Chart

This Helm chart deploys the go-lock OAuth2/OpenID Connect service to Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- A PostgreSQL database

## Installing the Chart

To install the chart with the release name `my-go-lock`:

```bash
# Add your container registry (if using private registry)
helm install my-go-lock ./deploy/helm/go-lock \
  --set image.repository=your-registry/go-lock \
  --set image.tag=latest \
  --set ingress.hosts[0].host=auth.yourdomain.com \
  --set database.url="postgres://user:password@postgresql:5432/golock?sslmode=disable"
```

## Configuration

The following table lists the configurable parameters and their default values.

### Application Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `3` |
| `image.repository` | Image repository | `go-lock` |
| `image.tag` | Image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `server.port` | Server port | `8080` |
| `server.environment` | Server environment | `production` |
| `server.baseURL` | Base URL (auto-generated from ingress) | `""` |

### Database Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.url` | Database connection string | `postgres://username:password@postgresql:5432/golock?sslmode=disable` |
| `database.maxOpenConns` | Max open connections | `25` |
| `database.maxIdleConns` | Max idle connections | `5` |

### Ingress Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `true` |
| `ingress.className` | Ingress class | `nginx` |
| `ingress.hosts[0].host` | Hostname | `auth.yourdomain.com` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `secrets.apiKey` | API key | `your_secure_api_key_here` |
| `secrets.csrfSecret` | CSRF secret | `your-32-character-csrf-secret-key` |
| `secrets.sessionSecret` | Session secret | `your-32-character-session-secret` |

### Autoscaling Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `true` |
| `autoscaling.minReplicas` | Minimum replicas | `3` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | CPU target | `70` |

## Production Deployment

For production deployments, you should:

1. **Use external secret management:**
   ```yaml
   externalSecrets:
     enabled: true
   ```

2. **Configure proper ingress:**
   ```yaml
   ingress:
     hosts:
       - host: auth.yourdomain.com
     tls:
       - secretName: go-lock-tls
         hosts:
           - auth.yourdomain.com
   ```

3. **Set resource limits:**
   ```yaml
   resources:
     limits:
       cpu: 500m
       memory: 512Mi
     requests:
       cpu: 100m
       memory: 128Mi
   ```

## Examples

### Development Deployment

```bash
helm install go-lock-dev ./deploy/helm/go-lock \
  --set server.environment=development \
  --set ingress.enabled=false \
  --set autoscaling.enabled=false \
  --set replicaCount=1
```

### Production Deployment

```bash
helm install go-lock-prod ./deploy/helm/go-lock \
  --set image.repository=your-registry/go-lock \
  --set image.tag=v1.0.0 \
  --set ingress.hosts[0].host=auth.yourdomain.com \
  --set database.url="postgres://user:$(DATABASE_PASSWORD)@postgresql:5432/golock?sslmode=require" \
  --set secrets.apiKey="$(API_KEY)" \
  --set secrets.csrfSecret="$(CSRF_SECRET)" \
  --set secrets.sessionSecret="$(SESSION_SECRET)"
```

## Monitoring

The chart includes:
- Health checks (readiness and liveness probes)
- Horizontal Pod Autoscaler
- Pod Disruption Budget
- Service monitoring annotations

## Uninstalling

```bash
helm uninstall my-go-lock
```