import { defineRailway, github, preserve, project, redis, service, volume } from "railway/iac";

// The Railway project the API and worker run in, as Railway's infrastructure-as-code file
// (DECISIONS.md §218). It replaces `infrastructure/railway/api.json` and `worker.json`, whose
// Config as Code format Railway stops reading on 2026-12-01.
//
// Railway does not read this file on deploy: a push to `main` builds what is set on the
// services, and a change here reaches them only through `railway config apply`. The file is
// the whole project, and apply deletes what it leaves out, so `railway config plan` comes
// first, every time (`docs/DEPLOYMENT.md` §2).
//
// A restart policy is not named: Railway restarts on failure by default and stores that
// default as no setting, so naming it would leave the plan with a change it never makes.
//
// Secrets stay on Railway: every variable is `preserve()`, which keeps the value set there
// and only says that the variable exists.

const shared = {
  API_URL: preserve(),
  APP_ENV: preserve(),
  APP_URL: preserve(),
  AWS_ACCESS_KEY_ID: preserve(),
  AWS_PRINCIPAL_ARN: preserve(),
  AWS_SECRET_ACCESS_KEY: preserve(),
  AZURE_CLIENT_ID: preserve(),
  AZURE_CLIENT_SECRET: preserve(),
  AZURE_CONSENT_STATE_SECRET: preserve(),
  AZURE_REDIRECT_URI: preserve(),
  AZURE_TENANT_ID: preserve(),
  CORS_ORIGINS: preserve(),
  DATABASE_OWNER_URL: preserve(),
  DATABASE_URL: preserve(),
  DATABASE_WORKER_URL: preserve(),
  REDIS_URL: preserve(),
  SUPABASE_JWT_SECRET: preserve(),
  SUPABASE_PUBLISHABLE_KEY: preserve(),
  SUPABASE_SECRET_KEY: preserve(),
  SUPABASE_URL: preserve(),
};

export default defineRailway(() => {
  const Redis = redis("Redis", { region: "ams" });
  Redis.deploy = {
    startCommand:
      '/bin/sh -c "rm -rf $RAILWAY_VOLUME_MOUNT_PATH/lost+found/ && exec docker-entrypoint.sh redis-server --requirepass $REDIS_PASSWORD --save 60 1 --dir $RAILWAY_VOLUME_MOUNT_PATH"',
  };
  Redis.networking = { privateNetworkEndpoint: "redis" };
  const redisVolume = volume("redis-volume", {
    alerts: { usage: { "100": {}, "80": {}, "95": {} } },
    allowOnlineResize: true,
    region: "ams",
    sizeMB: 500,
  });

  // The API: the service with the public domain. Its start command runs the migrations
  // before it serves, so a deploy that cannot migrate never answers.
  const api = service("humorous-passion", {
    source: github("r3iX0/CSPM-SaaS", { checkSuites: true }),
    build: { builder: "DOCKERFILE", dockerfilePath: "infrastructure/docker/api.Dockerfile" },
    deploy: {
      startCommand:
        "sh -c 'alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}'",
      healthcheckPath: "/health",
      healthcheckTimeout: 300,
      restartPolicyMaxRetries: 3,
    },
    replicas: { ams: 1 },
    env: shared,
  });

  // The worker: the same image, running Celery and its beat schedule.
  const worker = service("CSPM-SaaS", {
    source: github("r3iX0/CSPM-SaaS", { checkSuites: true }),
    build: { builder: "DOCKERFILE", dockerfilePath: "infrastructure/docker/api.Dockerfile" },
    deploy: {
      startCommand:
        "celery -A app.workers.celery_app.celery_app worker --beat --schedule=/tmp/celerybeat-schedule --queues=celery,collect,analyze --loglevel=INFO --concurrency=2",
      restartPolicyMaxRetries: 3,
    },
    replicas: { "us-west2": 1 },
    networking: { privateNetworkEndpoint: "cspm-saas" },
    env: shared,
  });

  return project("skillful-illumination", {
    resources: [api, worker, Redis, redisVolume],
  });
});
