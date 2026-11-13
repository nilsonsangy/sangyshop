# =============================================================================
# cloud.config.example.ps1  --  SangyShop multi-cloud deploy configuration TEMPLATE
# =============================================================================
#
# HOW TO USE:
#   1. Copy this file to  cloud.config.ps1  (in this same folder).
#   2. Fill in the placeholder values (<...>) for the cloud(s) you will use.
#   3. Set a globally-unique suffix (3-24 lowercase letters/digits) -- see below.
#   cloud.config.ps1 is git-ignored, so your account details never enter version control.
#
# SECURITY -- READ THIS:
#   * This file MUST NOT contain any password, access key, token, or connection string.
#     The database password is GENERATED at deploy time and stored ONLY in the cloud's
#     secret manager (AWS Secrets Manager / Azure Key Vault / GCP Secret Manager); it is
#     delivered to the container as the file /run/secrets/db_password. It never lives here.
#   * Cloud CLI credentials come from your authenticated CLI session (aws/az/gcloud),
#     NOT from this file.
#
# The values below are SAFE DEFAULTS and PLACEHOLDERS only -- no real account identifiers.
# =============================================================================

@{

    # -------------------------------------------------------------------------
    # Globally-unique suffix
    # -------------------------------------------------------------------------
    # Some cloud resource names must be unique across the ENTIRE cloud (not just
    # your account): Azure Container Registry (ACR), Azure Key Vault, and
    # GCP bucket-like names. Scripts append this suffix to those names.
    #
    # RULES: 3 to 24 characters, lowercase letters (a-z) and digits (0-9) ONLY.
    # Pick something unlikely to collide, e.g. your initials + a few digits.
    UniqueSuffix = "<your-unique-suffix>"   # e.g. "abc12345"

    # -------------------------------------------------------------------------
    # Common -- shared, cloud-independent values (safe defaults; usually leave as-is)
    # -------------------------------------------------------------------------
    Common = @{
        AppName  = "sangyshop"   # base name used to derive all resource names
        DbName   = "sangyshop"   # database name created on the managed Postgres instance
        DbUser   = "sangyshop"   # database admin/login username (NOT a secret)
        ImageTag = "hardened"    # only the hardened variant is ever deployed

        # Optional: path to a local NimbusDFIR checkout, used only by the incident
        # response helper scripts. NIMBUSDFIR_PATH (environment) is checked first.
        # NimbusDfirPath = "<path-to-your-NimbusDFIR-checkout>"
    }

    # -------------------------------------------------------------------------
    # AWS  (ECR + RDS + Secrets Manager + ECS Fargate / EKS)
    # -------------------------------------------------------------------------
    Aws = @{
        Region     = "us-east-1"            # safe default region
        AccountId  = "<your-aws-account-id>"   # 12-digit AWS account id (placeholder)
        EcrRepo    = "sangyshop"            # ECR repository name
        EcsCluster = "sangyshop-lab"        # ECS Fargate cluster name (Docker-only modality)
        EksCluster = "sangyshop-lab"        # EKS cluster name (Kubernetes modality)

        # EC2 modality (Get-CloudConfig -Cloud Aws -Modality ec2). No secrets here.
        Ec2 = @{
            InstanceType    = "t3.small"        # EC2 instance type
            DbInstanceClass = "db.t4g.micro"    # RDS PostgreSQL instance class
            BucketBase      = "sangyshop-lab"   # S3 bucket base name (suffix is appended)
            VolumeGb        = 20                # EBS gp3 volume size in GB
        }
    }

    # -------------------------------------------------------------------------
    # Azure  (ACR + Flexible Server + Key Vault + ACI / AKS)
    # -------------------------------------------------------------------------
    # NOTE: AcrName and KeyVault must be GLOBALLY unique. The scripts append
    # UniqueSuffix (above) to the base names below, so keep these base names short
    # (ACR allows alphanumeric only; combined length limits apply).
    Azure = @{
        Location      = "eastus"                # safe default region
        ResourceGroup = "sangyshop-lab-rg"      # resource group (created if absent)
        AcrNameBase   = "sangyshoplab"          # ACR base; final name = AcrNameBase + UniqueSuffix (alnum only)
        KeyVaultBase  = "sangyshop-kv"          # Key Vault base; final name = KeyVaultBase + "-" + UniqueSuffix
        AciName       = "sangyshop-lab-aci"     # Azure Container Instance name (Docker-only modality)
        AksCluster    = "sangyshop-lab-aks"     # AKS cluster name (Kubernetes modality)

        # VM modality (Get-CloudConfig -Cloud Azure -Modality vm). No secrets here.
        Vm = @{
            VmSize            = "Standard_B1ms"       # VM size
            PgSku             = "Standard_B1ms"       # PostgreSQL Flexible Server SKU
            PgStorageGb       = 32                    # PostgreSQL storage in GB
            ResourceGroupBase = "sangyshop-lab"       # Lab resource group base name
            EvidenceGroupBase = "sangyshop-evidence"  # Evidence resource group base name
        }
    }

    # -------------------------------------------------------------------------
    # GCP  (Artifact Registry + Cloud SQL + Secret Manager + Cloud Run / GKE)
    # -------------------------------------------------------------------------
    Gcp = @{
        ProjectId    = "<your-gcp-project-id>"   # GCP project id (placeholder)
        Region       = "us-central1"             # safe default region
        ArRepo       = "sangyshop"               # Artifact Registry repository name
        CloudRunName = "sangyshop-lab"           # Cloud Run service name (Docker-only modality)
        GkeCluster   = "sangyshop-lab"           # GKE cluster name (Kubernetes modality)
    }

}
