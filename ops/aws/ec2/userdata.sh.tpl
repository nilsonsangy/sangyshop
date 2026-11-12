#!/bin/bash
# =============================================================================
# SangyShop EC2 user-data template (Amazon Linux 2023).
#
# deploy.ps1 renders this file by replacing the @@TOKEN@@ placeholders below and
# passes the result to `aws ec2 run-instances --user-data file://...`.
# The rendered script contains NO secret value: the DB password is fetched at
# boot from Secrets Manager through the instance profile (sangyshop-ec2-role).
#
# What it does:
#   1. Installs Docker, git and the AWS CLI (already present on AL2023).
#   2. Clones the SangyShop code (GitHub or CodeCommit) and builds the VULNERABLE
#      image (the default Dockerfile at the repo root).
#   3. Runs the container with the awslogs log driver (CloudWatch Logs group
#      @@LOG_GROUP@@), a /lab volume, and APP_MODE=vulnerable, DB_BACKEND=pg
#      pointing to the RDS endpoint.
# IMDSv2 (required, hop limit 2) is enforced by deploy.ps1 in the run-instances
# --metadata-options; hop limit 2 lets the container reach IMDS for the S3 SDK.
# =============================================================================
set -euo pipefail
exec > >(tee -a /var/log/sangyshop-userdata.log) 2>&1

REGION="@@REGION@@"
REPO_KIND="@@REPO_KIND@@"          # github | codecommit
REPO_URL="@@REPO_URL@@"
SECRET_ID="@@SECRET_ID@@"
DB_HOST="@@DB_HOST@@"
DB_PORT="5432"
DB_NAME="@@DB_NAME@@"
DB_USER="@@DB_USER@@"
S3_BUCKET="@@S3_BUCKET@@"
LOG_GROUP="@@LOG_GROUP@@"
LAB_MODE_VALUE="@@LAB_MODE@@"      # 1 = lab marker + /debug/config routes, 0 = off
APP_PORT="3000"
APP_DIR="/opt/sangyshop"
ENV_FILE="/etc/sangyshop/app.env"

echo "[userdata] installing packages"
dnf install -y docker git awscli-2 2>/dev/null || dnf install -y docker git
systemctl enable --now docker

echo "[userdata] cloning SangyShop (${REPO_KIND})"
mkdir -p "${APP_DIR}"
if [ "${REPO_KIND}" = "codecommit" ]; then
  git config --system credential.helper '!aws codecommit credential-helper $@'
  git config --system credential.UseHttpPath true
fi
if [ -d "${APP_DIR}/.git" ]; then
  git -C "${APP_DIR}" pull --ff-only
else
  git clone "${REPO_URL}" "${APP_DIR}"
fi

echo "[userdata] building the vulnerable image"
docker build -t sangyshop:insecure "${APP_DIR}"

# /lab volume: holds the lab-only "forgotten" file served by /debug/config.
mkdir -p /lab
chmod 755 /lab

echo "[userdata] fetching the DB password from Secrets Manager (not logged)"
mkdir -p "$(dirname "${ENV_FILE}")"
DB_PASSWORD_VALUE="$(aws secretsmanager get-secret-value \
  --secret-id "${SECRET_ID}" --region "${REGION}" \
  --query SecretString --output text)"
( umask 077
  {
    echo "APP_MODE=vulnerable"
    echo "DB_BACKEND=pg"
    echo "DB_HOST=${DB_HOST}"
    echo "DB_PORT=${DB_PORT}"
    echo "DB_NAME=${DB_NAME}"
    echo "DB_USER=${DB_USER}"
    echo "DB_SSL=require"
    echo "DB_PASSWORD=${DB_PASSWORD_VALUE}"
    echo "OBJECT_STORE=s3"
    echo "S3_BUCKET=${S3_BUCKET}"
    echo "AWS_REGION=${REGION}"
    echo "LAB_CLOUD=aws"
    echo "LAB_LEAKED_FILE=/lab/leaked.json"
    if [ "${LAB_MODE_VALUE}" = "1" ]; then echo "LAB_MODE=1"; fi
    echo "PORT=${APP_PORT}"
  } > "${ENV_FILE}" )
unset DB_PASSWORD_VALUE

echo "[userdata] starting the container"
docker rm -f sangyshop 2>/dev/null || true
docker run -d --name sangyshop --restart unless-stopped \
  --log-driver awslogs \
  --log-opt awslogs-region="${REGION}" \
  --log-opt awslogs-group="${LOG_GROUP}" \
  --log-opt awslogs-create-group=true \
  --env-file "${ENV_FILE}" \
  -v /lab:/lab \
  -p "${APP_PORT}:${APP_PORT}" \
  sangyshop:insecure

echo "[userdata] done"
