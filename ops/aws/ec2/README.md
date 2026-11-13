# AWS EC2 + RDS lab (EC2 deployment)

Deploys the **deliberately vulnerable** SangyShop on a single EC2 instance with an
RDS PostgreSQL database, for the cloud incident-response lab. Use an
isolated, throwaway AWS account only. Default region: `us-east-1`.

```text
ops/aws/ec2/
├── deploy.ps1        # create everything (-WhatIf supported)
├── teardown.ps1      # remove everything, idempotent (-WhatIf supported)
├── stop-lab.ps1      # intermediate stop of EC2 + RDS (nothing deleted)
├── start-lab.ps1     # resume after stop-lab.ps1
├── userdata.sh.tpl   # EC2 user-data template rendered by deploy.ps1
└── README.md
```

All scripts are Windows PowerShell 5.1 compatible, print every external command
before running it, and write all output and errors in English.

## What gets created

| Order | Resource | Notes |
|---|---|---|
| 1 | VPC `sangyshop-lab-vpc` (192.168.81.0/24), internet gateway, 1 public + 2 private subnets, public route table | Private subnets host RDS only. |
| 1 | Dedicated NACL on the public subnet | Rule 900 allows traffic; rules 1-899 are reserved for DENY entries added later by the lab blocker. |
| 2 | Security group `sangyshop-lab-app-sg` | Port 3000 from the `-AllowedSourceRanges` /32 only. No SSH port. |
| 2 | Security group `sangyshop-lab-db-sg` | 5432 from the instance security group only (no CIDR rule). |
| 3 | IAM role `sangyshop-ec2-role` + instance profile | App bucket read/write, `secretsmanager:GetSecretValue` on the DB secret, CloudWatch Logs, `AmazonSSMManagedInstanceCore`. |
| 4 | S3 bucket `<BucketBase>-<UniqueSuffix>` | Block Public Access on (all 4 settings). |
| 5 | Secret `sangyshop/ec2/db_password` | 32-character generated password. |
| 6 | RDS PostgreSQL `sangyshop-lab-pg` | Class from `Aws.Ec2.DbInstanceClass`, single-AZ, not publicly accessible, TLS. |
| 7 | CodeCommit repo `sangyshop` | Only with `-Repo codecommit`. |
| 8 | EC2 instance `sangyshop-lab-ec2` | Amazon Linux 2023, gp3 encrypted root volume, IMDSv2 required with hop limit 2, access through SSM Session Manager. |

Every taggable resource carries the lab tags `lab`, `run-id` and `component`
(built by `Get-LabTags`). Each resource is also recorded in the lab manifest
(`$HOME/.sangyshop-lab/manifest-sangyshop-lab-aws.json`, or `LAB_MANIFEST_PATH`) with
`Add-LabManifestEntry`. The manifest lives outside the repository.

The identities `lab-operator` (the human running these scripts, with MFA) and
`sangyshop-lab-leaked` (the exposed-credential IAM user) are **not** created by
these scripts. `sangyshop-ec2-role` is the application identity. The account-wide
full AWS teardown removes the leaked user and its access keys.

## Configuration

Copy `ops/cloud.config.example.ps1` to `ops/cloud.config.ps1` and fill in
`Aws.Region`, `Aws.AccountId` and the `Aws.Ec2` section:

```powershell
Ec2 = @{
    InstanceType    = "t3.small"
    DbInstanceClass = "db.t4g.micro"
    BucketBase      = "sangyshop-lab"
    VolumeGb        = 20
}
```

The config file must never contain passwords or keys. The DB password is generated
at deploy time and stored only in Secrets Manager.

## deploy.ps1

```powershell
./ops/aws/ec2/deploy.ps1 -AllowedSourceRanges 203.0.113.10/32 -WhatIf   # dry run
./ops/aws/ec2/deploy.ps1 -AllowedSourceRanges 203.0.113.10/32           # real run
```

| Parameter | Meaning |
|---|---|
| `-AllowedSourceRanges` | **Required.** Single IPv4 hosts in `/32` form. |
| `-WhatIf` | Print the ordered command list. Nothing is executed, created or written to the manifest. Exit 0. |
| `-RunId` | Run identifier `yyyyMMddTHHmmssZ-xxxx` for the `run-id` tag. Default: `New-RunId`. |
| `-Repo github\|codecommit` | Where the instance gets the code. Default `github` (`https://github.com/nilsonsangy/sangyshop.git`). With `codecommit`, if the repository cannot be created the script falls back to GitHub once and does not retry. Push the code to CodeCommit before the instance boots. |
| `-NoLabMode` | Do not set `LAB_MODE=1` (disables the lab marker and `/debug/config` routes). |
| `-ConfigPath` | Alternative config file. |

Behavior:

- `0.0.0.0/0`, `::/0`, a missing value or any non-`/32` value stops the script with
  exit 1 and a message on stderr **before any external command runs**.
- If a resource fails to be created, the script exits 1, names the failed resource
  on stderr and lists the resources already created. Remove them with
  `teardown.ps1`.
- The DB password is never written to a versioned file, a log or an echoed command.
  It reaches the AWS CLI only through a transient `file://` temp file that is wiped
  afterwards.
- Re-running is convergent: existing resources are reused.

Expected final output: `Application URL: http://<public-ip>:3000`. The first boot
takes a few minutes (Docker install and image build). Verify with a browser from the
allowed IP: log in with a test account and list products.

### User data (`userdata.sh.tpl`)

Rendered by `deploy.ps1` (placeholders `@@NAME@@`) and passed with
`--user-data file://`. It contains no secret. On boot it:

1. installs Docker and git;
2. clones the SangyShop code (GitHub or CodeCommit) and builds the vulnerable image;
3. reads the DB password from Secrets Manager through the instance profile;
4. runs the container with `--log-driver awslogs` (log group `/sangyshop/app`,
   created by the driver), a `/lab` volume, `APP_MODE=vulnerable`,
   `DB_BACKEND=pg`, `DB_SSL=require`, `OBJECT_STORE=s3` and `LAB_MODE=1`.

The vulnerable variant reads `DB_PASSWORD` from the environment by design, so the
password sits in `/etc/sangyshop/app.env` (mode 600) on the instance. That is part of
the lab and must never be copied to hardened deployments.

IMDSv2 is required with hop limit 2 (set in `run-instances --metadata-options`), so
the container can reach the metadata service and the S3 SDK gets role credentials.

## teardown.ps1

```powershell
./ops/aws/ec2/teardown.ps1 -WhatIf   # list what would be removed
./ops/aws/ec2/teardown.ps1 -Force    # remove, no prompt
```

Order (inverse of creation): EC2 instance, RDS instance and DB subnet group, secret,
S3 bucket, IAM instance profile and role, CodeCommit repository, log group
`/sangyshop/app`, then security groups, subnets, NACL, route table, internet gateway
and VPC.

- Exit 0 only when no EC2 deployment resource remains.
- Re-running after a successful teardown skips what is gone, prints
  `Teardown complete: no EC2 deployment resources remain (nothing to remove).` and exits 0
  in a few seconds.
- If a resource cannot be removed, its type and identifier are listed on stderr, the
  other resources are still removed and the exit code is non-zero.
- The detection stack, evidence snapshots and the exposed credential are outside this
  script. The account-wide full AWS teardown prevails and is the recommended command
  to remove the whole lab.

After teardown, check the console in the lab region for leftovers: RDS, EC2, EBS
volumes, snapshots, Elastic IPs, NAT gateways and load balancers.

## stop-lab.ps1 / start-lab.ps1

```powershell
./ops/aws/ec2/stop-lab.ps1    # end of the lab day
./ops/aws/ec2/start-lab.ps1   # next day
```

`stop-lab.ps1` stops the EC2 instance, then the RDS instance. `start-lab.ps1` starts
RDS, waits until it is available, then starts EC2 and prints the new public URL. Both
accept `-WhatIf` and `-ConfigPath`, and print these warnings before running anything:

- a stopped RDS instance **restarts automatically after 7 days**;
- EBS and RDS storage (and any Elastic IP) **keep being billed** while stopped;
- stopping is **not** a teardown. Use `teardown.ps1` or full AWS teardown to stop all
  billing.

The public IP changes on each start because no Elastic IP is used. The container uses
`--restart unless-stopped`, so the app returns by itself after the instance starts.

## Next: the incident response lab

After the deploy, the detection stack, the readiness check and the response helpers live in
`ops/aws/ir-lab/` of this repository:

1. `ops/aws/ir-lab/detection/enable-all.ps1` creates CloudTrail, the log metric filter, the
   brute-force alarm and the e-mail alert. The address comes from `-Email`, `LAB_ALERT_EMAIL` or
   `ops/.env` (copy `ops/.env.example`). It exits with code 4, naming this `deploy.ps1`, when the
   application log group `/sangyshop/app` does not exist.
2. Confirm the subscription e-mail, then run `ops/aws/ir-lab/check-detection-ready.ps1`. It writes
   the readiness stamp that `attack-simulation/attack.js` requires.
3. Run the attack, then `ops/aws/ir-lab/print-response-commands.ps1`. It prints native
   `aws` commands for evidence collection and containment and runs none of them.

Permissions for these scripts are granted through the lab IAM group; see `ops/aws/iam/README.md`
and the permission tables in `ops/README.md`. `ops/aws/ir-lab/full-teardown.ps1` removes the whole
lab.

## Safety checklist

- Isolated, throwaway AWS account; one region.
- Ingress limited to your own /32. Never open the app to the internet.
- Run `stop-lab.ps1` every day and `teardown.ps1` (or full AWS teardown) when done.
- Never commit `cloud.config.ps1` or any `lab-manifest*.json`.
