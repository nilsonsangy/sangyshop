#cloud-config
# =============================================================================
# SangyShop VULNERABLE lab VM -- cloud-init template (ops/azure/vm/deploy.ps1)
# =============================================================================
# deploy.ps1 replaces every placeholder written between double at-signs below with a NON-SECRET value and passes the
# rendered file to `az vm create --custom-data`. This template never contains the
# database password: at first boot the VM reads it from Key Vault with its
# user-assigned managed identity and writes it only to a root-only env file.
#
# Azure Monitor Agent (AMA): the agent and the Data Collection Rule (DCR) are
# Azure resources, not packages. deploy.ps1 installs the AzureMonitorLinuxAgent VM
# extension and associates the DCR with this VM AFTER the VM exists. This template
# prepares everything the DCR reads: the rsyslog drop-in below writes the
# container's syslog stream (facility local0) to /var/log/sangyshop/app.log, which
# is the file pattern of the DCR "custom text logs" source feeding SangyShopApp_CL.
#
# SECURITY: SangyShop is deliberately vulnerable. Keep ingress restricted to your
# own /32 and run teardown.ps1 when the lab ends.

package_update: true
package_upgrade: false
packages:
  - ca-certificates
  - curl
  - git
  - jq
  - rsyslog
  - docker.io

write_files:
  # rsyslog: write only the message body (one JSON object per line) of facility
  # local0 to the file collected by AMA. The leading space that follows the
  # "sangyshop[pid]:" tag is trimmed so the line is valid JSON for parse_json().
  - path: /etc/rsyslog.d/30-sangyshop.conf
    owner: root:root
    permissions: '0644'
    content: |
      template(name="SangyShopRaw" type="string" string="%msg:2:$%\n")
      if ($syslogfacility-text == "local0") then {
        action(type="omfile" file="/var/log/sangyshop/app.log" template="SangyShopRaw" fileCreateMode="0644")
      }

  # Non-secret application environment. The DB password is appended at boot by
  # sangyshop-start.sh (never written by cloud-init).
  - path: /etc/sangyshop/app.env.base
    owner: root:root
    permissions: '0600'
    content: |
      APP_MODE=vulnerable
      DB_BACKEND=pg
      DB_HOST=@@PG_FQDN@@
      DB_PORT=5432
      DB_NAME=@@DB_NAME@@
      DB_USER=@@DB_USER@@
      DB_SSL=require
      PORT=@@APP_PORT@@
      STRUCTURED_LOGS=on
      OBJECT_STORE=azure-blob
      AZURE_STORAGE_ACCOUNT=@@STORAGE_ACCOUNT@@
      AZURE_STORAGE_CONTAINER=@@STORAGE_CONTAINER@@
      AZURE_CLIENT_ID=@@IDENTITY_CLIENT_ID@@
      LAB_MODE=@@LAB_MODE@@
      LAB_CLOUD=azure
      LAB_LEAKED_FILE=/lab/leaked.json

  - path: /usr/local/sbin/sangyshop-start.sh
    owner: root:root
    permissions: '0750'
    content: |
      #!/bin/bash
      # Fetch the DB password from Key Vault with the VM managed identity, build the
      # vulnerable image and start it with the syslog log driver.
      set -euo pipefail
      umask 077
      exec > >(tee -a /var/log/sangyshop-start.log) 2>&1

      KV_NAME="@@KEY_VAULT_NAME@@"
      SECRET_NAME="@@SECRET_NAME@@"
      CLIENT_ID="@@IDENTITY_CLIENT_ID@@"
      REPO_URL="@@REPO_URL@@"
      APP_PORT="@@APP_PORT@@"

      # Token for Key Vault from IMDS. Retry: RBAC assignments can take minutes to propagate.
      PASSWORD=""
      for attempt in $(seq 1 40); do
        TOKEN=$(curl -sf -H "Metadata:true" \
          "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=${CLIENT_ID}" \
          | jq -r '.access_token // empty') || TOKEN=""
        if [ -n "${TOKEN}" ]; then
          PASSWORD=$(curl -sf -H "Authorization: Bearer ${TOKEN}" \
            "https://${KV_NAME}.vault.azure.net/secrets/${SECRET_NAME}?api-version=7.4" \
            | jq -r '.value // empty') || PASSWORD=""
        fi
        if [ -n "${PASSWORD}" ]; then break; fi
        echo "Key Vault secret not available yet (attempt ${attempt}/40); retrying in 15 s"
        sleep 15
      done
      if [ -z "${PASSWORD}" ]; then
        echo "ERROR: could not read secret '${SECRET_NAME}' from Key Vault '${KV_NAME}'." >&2
        exit 1
      fi

      # Root-only env file consumed with --env-file (the value never appears in `ps`).
      install -d -m 0700 /etc/sangyshop
      cp /etc/sangyshop/app.env.base /etc/sangyshop/app.env
      printf 'DB_PASSWORD=%s\n' "${PASSWORD}" >> /etc/sangyshop/app.env
      chmod 0600 /etc/sangyshop/app.env
      unset PASSWORD TOKEN

      # Build the vulnerable image (root Dockerfile = default insecure baseline).
      if [ ! -d /opt/sangyshop/.git ]; then
        git clone --depth 1 "${REPO_URL}" /opt/sangyshop
      fi
      docker build -t sangyshop:vulnerable /opt/sangyshop

      docker rm -f sangyshop >/dev/null 2>&1 || true
      docker run -d --name sangyshop --restart unless-stopped \
        -p "${APP_PORT}:${APP_PORT}" \
        --log-driver syslog \
        --log-opt syslog-facility=local0 \
        --log-opt tag=sangyshop \
        --env-file /etc/sangyshop/app.env \
        -v /lab:/lab:ro \
        sangyshop:vulnerable
      echo "SangyShop (vulnerable) started on port ${APP_PORT}"

runcmd:
  - [ install, -d, -o, syslog, -g, adm, -m, '0755', /var/log/sangyshop ]
  - [ install, -d, -m, '0755', /lab ]
  - [ systemctl, enable, --now, docker ]
  - [ systemctl, restart, rsyslog ]
  - [ /usr/local/sbin/sangyshop-start.sh ]

final_message: "SangyShop lab VM initialised after $UPTIME seconds"
