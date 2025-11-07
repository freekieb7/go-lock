# Kubernetes Health Endpoints

This document describes the health check endpoints designed specifically for Kubernetes deployments.

## Health Endpoints

### 1. `/health` - Comprehensive Health Check
- **Purpose**: Complete system health overview for monitoring and debugging
- **Timeout**: 10 seconds
- **Returns**: Detailed component health status
- **Use Cases**: 
  - External monitoring systems (Prometheus, DataDog, etc.)
  - Debugging and troubleshooting
  - Health dashboards

**Example Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-10T14:30:00Z",
  "version": "1.0.0",
  "components": {
    "database": {
      "status": "healthy",
      "message": "database connection successful",
      "latency_ms": 15000000,
      "last_checked": "2025-11-10T14:30:00Z",
      "critical": true
    },
    "cache": {
      "status": "healthy",
      "message": "cache operational",
      "latency_ms": 5000000,
      "last_checked": "2025-11-10T14:30:00Z",
      "critical": false
    },
    "application": {
      "status": "healthy",
      "message": "application services operational",
      "latency_ms": 1000000,
      "last_checked": "2025-11-10T14:30:00Z",
      "critical": false
    }
  }
}
```

### 2. `/health/live` - Kubernetes Liveness Probe
- **Purpose**: Determine if container should be restarted
- **Timeout**: 3 seconds
- **Checks**: Process responsiveness only
- **K8s Usage**: `livenessProbe`

**Configuration:**
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
```

### 3. `/health/ready` - Kubernetes Readiness Probe
- **Purpose**: Determine if container should receive traffic
- **Timeout**: 5 seconds
- **Checks**: Database connectivity and critical dependencies
- **K8s Usage**: `readinessProbe`

**Configuration:**
```yaml
readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 3
```

### 4. `/health/startup` - Kubernetes Startup Probe
- **Purpose**: Handle slow-starting containers
- **Timeout**: 30 seconds
- **Checks**: Same as readiness but with longer timeout
- **K8s Usage**: `startupProbe`

**Configuration:**
```yaml
startupProbe:
  httpGet:
    path: /health/startup
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 30
  failureThreshold: 10  # 50 seconds total
```

## Health Status Meanings

### Status Levels
- **healthy**: All systems operational
- **degraded**: Non-critical components failing (e.g., cache unavailable)
- **unhealthy**: Critical components failing (e.g., database unavailable)

### HTTP Response Codes
- **200 OK**: Service is healthy or degraded
- **503 Service Unavailable**: Service is unhealthy

## Component Health Details

### Database (Critical)
- **Healthy**: Connection successful, response < 100ms
- **Degraded**: Connection successful, response 100ms-5s
- **Unhealthy**: Connection failed or response > 5s

### Cache (Non-Critical)
- **Healthy**: Redis connection and operations successful
- **Degraded**: Redis unavailable (service continues without cache)
- **Unhealthy**: N/A (cache failures don't make service unhealthy)

### Application (Non-Critical)
- **Healthy**: Application-level checks pass
- **Degraded**: Some application features unavailable
- **Unhealthy**: Core application logic failing

## Kubernetes Integration

### Probe Timing Strategy
1. **Startup Probe**: Allows 50 seconds for initial startup
2. **Readiness Probe**: Quick checks every 5 seconds once started
3. **Liveness Probe**: Conservative checks every 10 seconds

### Failure Handling
- **Liveness Failure**: Container restart (last resort)
- **Readiness Failure**: Remove from service endpoints (graceful)
- **Startup Failure**: Prevent container from entering ready state

### Best Practices
1. **Different Endpoints**: Use separate endpoints for different probe types
2. **Appropriate Timeouts**: Match timeouts to expected response times
3. **Failure Thresholds**: Allow for transient network issues
4. **Resource Limits**: Ensure health checks don't consume excessive resources

## Monitoring Integration

### Prometheus Metrics
The health endpoints provide structured data that can be scraped by Prometheus:

```yaml
- job_name: 'go-lock-health'
  static_configs:
  - targets: ['go-lock-service:80']
  metrics_path: /health
  scrape_interval: 30s
```

### Alerting Rules
```yaml
groups:
- name: go-lock-health
  rules:
  - alert: GoLockUnhealthy
    expr: go_lock_health_status != 1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Go-Lock service is unhealthy"
      description: "Go-Lock has been unhealthy for more than 2 minutes"
```

## Troubleshooting

### Common Issues
1. **Database Connection Failures**
   - Check database connectivity
   - Verify connection string and credentials
   - Check network policies and security groups

2. **Cache Degradation**
   - Service continues to function
   - Performance may be reduced
   - Check Redis connectivity and resources

3. **Slow Startup**
   - Increase startup probe timeout
   - Check resource limits
   - Review initialization dependencies

### Debug Commands
```bash
# Check health status
kubectl exec -it <pod-name> -- curl localhost:8080/health

# View probe events
kubectl describe pod <pod-name>

# Check logs for health check failures
kubectl logs <pod-name> | grep -i health
```