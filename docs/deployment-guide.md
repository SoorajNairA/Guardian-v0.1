# Deployment Guide

This guide provides comprehensive instructions for deploying the Guardian API to a production environment. It covers infrastructure requirements, environment configuration, database setup, and monitoring.

## Infrastructure Requirements

- **Compute**: A container orchestration platform like Kubernetes or a PaaS like Heroku/Railway is recommended. For a small-scale deployment, a single server with 2 vCPUs and 4GB RAM is a good starting point.
- **Database**: A PostgreSQL database is required for logging and API key management. We officially support and recommend [Supabase](https://supabase.com).
- **Cache**: A Redis instance is required for distributed rate limiting and caching.

## Environment Configuration

Guardian is configured via environment variables. The following variables are essential for a production deployment:

| Variable                      | Description                                                              
| :---------------------------- | :----------------------------------------------------------------------- 
| `ENV`                         | Set to `production` to enable optimizations and disable debug features.  
| `GUARDIAN_API_KEYS`           | A comma-separated list of fallback API keys if the database is unavailable. 
| `GEMINI_API_KEY`              | Your Google AI Studio API key for Gemini enrichment.                     
| `SUPABASE_URL`                | The URL of your Supabase project.                                        
| `SUPABASE_SERVICE_ROLE_KEY`   | Your Supabase service role key for administrative access.                
| `REDIS_URL`                   | The connection URL for your Redis instance (e.g., `redis://:password@host:port/0`). 
| `LOG_LEVEL`                   | Set to `INFO` for production. `DEBUG` for verbose logging.               
| `ALERTING_ENABLED`            | Set to `True` to enable webhook or email alerts.                         
| `ALERT_WEBHOOK_URL`           | The webhook URL to send critical alerts to (e.g., Slack, PagerDuty).     

## Database Setup (Supabase)

1.  **Create a Supabase Project**: If you don't have one, create a new project at [supabase.com](https://supabase.com).
2.  **Deploy Schema**: Use the SQL editor in your Supabase dashboard to run the schema definition from `supabase/schema.sql`. This will create the `api_keys` and `logs` tables.
3.  **Enable Row Level Security (RLS)**: For production, it is critical to enable RLS on your tables to prevent unauthorized data access. The provided schema includes basic RLS policies.
4.  **Configure Backups**: Configure daily backups for your Supabase project in the project settings.

## Container Deployment (Docker)

A `Dockerfile` is provided to build a container image for the API.

1.  **Build the Image**:

    ```bash
    docker build -t guardian-api:latest .
    ```

2.  **Run the Container**:

    ```bash
    docker run -d \
      -p 8000:8000 \
      --env-file .env.production \
      --name guardian-api \
      guardian-api:latest
    ```

    Ensure you have a `.env.production` file with all the required environment variables.

### Kubernetes

For Kubernetes deployments, you will need to create `Deployment`, `Service`, and `Secret` resources. A Helm chart is the recommended way to manage a production deployment.

## Monitoring and Observability

- **Health Checks**: The `GET /healthz` endpoint provides a detailed health status of the API and its dependencies. Configure your uptime monitoring service to poll this endpoint.
- **Metrics**: If `PROMETHEUS_METRICS_ENABLED` is `True`, the API will expose a `/metrics` endpoint for Prometheus to scrape. Use this to build dashboards in Grafana or your preferred monitoring tool.
- **Logging**: In a containerized environment, logs are typically written to `stdout` and collected by a log aggregator like Fluentd, Logstash, or a cloud provider's logging service (e.g., AWS CloudWatch, Google Cloud Logging).
- **Alerting**: Configure `ALERTING_ENABLED=True` and provide a webhook URL (`ALERT_WEBHOOK_URL`) to receive real-time alerts for high error rates, latency spikes, and unhealthy dependencies.

## Security Considerations

- **API Key Management**: Rotate API keys regularly. Use a secrets management system like HashiCorp Vault or your cloud provider's secrets manager to handle API keys and other sensitive environment variables.
- **Network Security**: Deploy the API behind a firewall and a reverse proxy or load balancer (like Nginx or Traefik). Configure TLS to ensure all traffic is encrypted.
- **Rate Limiting**: Adjust the default rate limits in the environment variables to match your expected traffic patterns and prevent abuse.

## Scaling

- **Horizontal Scaling**: The API is stateless and can be scaled horizontally by increasing the number of container replicas.
- **Database Scaling**: Monitor your Supabase instance's performance and upgrade your plan as needed.
- **Redis Scaling**: Use a managed Redis service that can be scaled easily as your caching and rate limiting needs grow.
