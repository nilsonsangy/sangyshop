# AWS incident response lab

Scripts that add a detection stack, an automatic blocker and a leaked credential to the SangyShop AWS deployment, so you can run an attack, detect it and respond to it. Everything is created with the lab tag (`lab=sangyshop-lab-aws`), recorded in a local manifest and removed by one teardown script.

The scripts never grant IAM permissions to themselves, never change a resource they did not create, and never run the attack or the response for you.

## Folder layout

```text
ops/aws/ir-lab/
  detection/    enable-*.ps1 and disable-*.ps1 (SNS, CloudTrail, CloudWatch Logs, flow logs, GuardDuty)
  blocker/      deploy-blocker.ps1, remove-blocker.ps1, lambda_function.py, policies/
  tests/        property tests of the blocker Lambda (pytest)
  check-detection-ready.ps1     read-only readiness check, writes the readiness stamp
  verify-lab-state.ps1          read-only report of which components exist
  print-response-commands.ps1   prints the response commands, runs nothing
  plant-leaked-credential.ps1   creates the leaked IAM user and the /lab/leaked.json file
  use-leaked-credential.ps1     uses that credential (at most 10 calls, no response content printed)
  full-teardown.ps1             removes everything the lab created
  verify-zero-cost.ps1          read-only list of what could still cost money
```

Names come from `ops/aws/AwsLabNames.ps1`, derived from `cloud.config.ps1`, so the application deployment and the lab scripts always agree.

## Prerequisites

- AWS CLI v2 signed in to the lab account, and PowerShell 5.1 or later.
- `ops/cloud.config.ps1` copied from `ops/cloud.config.example.ps1`, with `Aws.Region` and `Aws.AccountId` set. Every script also accepts `-Region`.
- The application deployed with `ops/aws/ec2/deploy.ps1`. It creates the application log group the alarm watches.
- Permissions listed in [Permissions needed before you start](#permissions-needed-before-you-start).

## The four steps

1. Build: deploy the application (`ops/aws/ec2/deploy.ps1`).
2. Detect: enable the detection stack and confirm it is ready.
3. Attack: run `attack-simulation/attack.js`.
4. Respond: print the response commands and run the ones you choose.

### 1. Build

```powershell
./ops/aws/ec2/deploy.ps1 -WhatIf   # review
./ops/aws/ec2/deploy.ps1
```

### 2. Detect

```powershell
./ops/aws/ir-lab/detection/enable-all.ps1 -Region us-east-1 -WhatIf
./ops/aws/ir-lab/detection/enable-all.ps1 -Region us-east-1
```

`-LabBucket` is optional. When omitted, it defaults to the app bucket that `ops/aws/ec2/deploy.ps1` creates (`Aws.Ec2.BucketBase` + `-` + `UniqueSuffix` from `ops/cloud.config.ps1`), or to the `s3-bucket` entry of the deploy component in the lab manifest. The CloudTrail component exits with 2 only when neither is available. The same default applies to `enable-cloudtrail.ps1`, `plant-leaked-credential.ps1` and `use-leaked-credential.ps1`.

`enable-all.ps1` runs SNS, CloudTrail, CloudWatch Logs (log group, metric filter and the brute-force alarm), VPC flow logs and GuardDuty, with one shared run id. A failure in one component does not stop the others. Switches: `-SkipFlowLogs`, `-SkipGuardDuty`, `-SkipDataEvents` (management events only), `-NonInteractive`. Each component also has its own `enable-*.ps1`.

The script starts with a read-only look at the account and prints one line per resource type (trail, log group, topic, detector) with the decision it will take: create, reuse a lab resource, reuse a resource it did not create, or blocked. A read that is denied or fails is treated as blocked, never as "missing".

When it finishes it prints the next steps as text only:

1. Open the AWS Notifications e-mail and confirm the subscription.
2. Run the readiness check.

```powershell
./ops/aws/ir-lab/check-detection-ready.ps1 -Region us-east-1
```

The check is read-only and passes only when all four conditions hold: the e-mail subscription is `Confirmed`, the brute-force alarm exists and has an action, the application log group exists, and the trail (created by the lab or reused) is logging. On success (exit 0) it writes the readiness stamp. With a subscription still in `PendingConfirmation` it exits with 4 and tells you to confirm the e-mail.

To see which components exist and which script creates a missing one:

```powershell
./ops/aws/ir-lab/verify-lab-state.ps1 -Region us-east-1
```

It makes only describe, get and list calls, prints one line per component, and exits with 1 if something is missing.

Optional auto-block of attacking IPs:

```powershell
./ops/aws/ir-lab/blocker/deploy-blocker.ps1 -Region us-east-1 -NaclId <nacl-id> -TopicArn <topic-arn> -WhatIf
./ops/aws/ir-lab/blocker/deploy-blocker.ps1 -Region us-east-1 -NaclId <nacl-id> -TopicArn <topic-arn>
```

The alarm triggers an EventBridge rule and a Lambda that adds inbound NACL deny entries numbered 100 to 199 for IPs with at least `-Threshold` failures (default 10). Private, loopback and link-local ranges are never blocked. The allow rules of the NACL must be numbered above 199. `remove-blocker.ps1` reverses it and removes the deny entries unless `-KeepBlocks` is set.

### 3. Attack

```powershell
node attack-simulation/attack.js
```

`attack.js` reads the readiness stamp before sending any request and refuses to start without a fresh one (see [Readiness stamp](#readiness-stamp)). It never calls a cloud API.

To plant and use the leaked credential:

```powershell
./ops/aws/ir-lab/plant-leaked-credential.ps1 -Region us-east-1 -WhatIf
./ops/aws/ir-lab/plant-leaked-credential.ps1 -Region us-east-1
./ops/aws/ir-lab/use-leaked-credential.ps1 -Region us-east-1
```

Both scripts accept `-LabBucket <app-bucket>` and `plant-leaked-credential.ps1` accepts `-InstanceId <instance-id>` to override the defaults. `-InstanceId` defaults to the `ec2-instance` entry of the deploy component in the lab manifest, then to `describe-instances` filtered by the lab Name tag (`sangyshop-lab-ec2`) and the lab tag (exactly one match, otherwise pass it). `plant-leaked-credential.ps1` needs `ssm:SendCommand`, which `lab-core.json` grants.

`plant-leaked-credential.ps1` creates a least-privilege IAM user (no console access; only `s3:ListBucket` and `s3:GetObject` on the app bucket), one access key, and writes the key to `/lab/leaked.json` on the instance with SSM. The secret is never printed. It is idempotent, and a same-named user without the lab tag stops the script with no change. `use-leaked-credential.ps1` makes at most 10 calls (`-MaxCalls`), prints only the API name and the status (`ok`, `denied`, `error`), and never prints response content.

### 4. Respond

```powershell
./ops/aws/ir-lab/print-response-commands.ps1 -Region us-east-1 -InstanceId <instance-id>
```

It prints ready-to-copy native `aws` commands: query CloudTrail events, list and read GuardDuty findings, snapshot the instance volume as evidence, move the instance to a quarantine security group, and contain the leaked IAM user (deactivate its access key and attach a deny-all inline policy). It never runs them, and it makes no AWS call. Values that depend on the live account (volume id, quarantine group id, access key id, time range) are printed as placeholders. The snapshot, the group change and the IAM changes modify the account, so review each command before running it. Exit codes: 0 commands printed, 2 configuration problem, 4 the attack evidence file (`attack-simulation/out/attack-steps.jsonl`) is missing, in which case the script names the attack step.

## Alert e-mail

The address that receives alerts comes from, in order: the `-Email` parameter, the `LAB_ALERT_EMAIL` environment variable, `ops/.env`, then an interactive prompt. Copy `ops/.env.example` to `ops/.env` and fill in the value; `ops/.env` is ignored by Git. With `-NonInteractive`, a missing address ends the script with exit code 2 instead of a prompt. The format is validated, and the address is never printed, only the source it came from.

## Readiness stamp

When `check-detection-ready.ps1` exits with 0 it writes `readiness-sangyshop-lab-aws.json` in the manifest folder (`$HOME/.sangyshop-lab/`, or the folder of `LAB_MANIFEST_PATH`, or the path given with `-StampPath`). It holds the lab name, region, a UTC time and the four check results. It holds no e-mail address and no resource ids. With any other exit code no stamp is written and an older stamp is left as it was. `attack.js` reads this file and nothing else. `attack.js --ack-no-detection` skips the check; use it only when you accept that the attack will not be detected.

## Reuse of existing infrastructure

The lab is additive. Before creating anything it reads the account and reuses what it can.

- CloudTrail: a trail that is multi-region, logging, and records read and write management events is reused as it is. If several qualify, the one named for the lab wins, then the first by name. The lab does not tag, modify, stop or remove a reused trail. If none qualifies, the script prints why, leaves the existing trails alone, and creates the lab trail only if the trail quota of the region allows it (otherwise exit 4).
- GuardDuty detector, SNS topic and log group that already exist are reused without tagging or changing their settings. The lab adds only its own e-mail subscription and metric filter.
- A lab resource that lost its tags is completed, not recreated.
- Reused resources are recorded in the manifest with ownership `reused`. Teardown removes only entries created by the lab or carrying the lab tag, and lists reused ones as `kept (not created by the lab)`.
- Each resource is written to the manifest right after it is created, so after a failure you can fix the cause and run the same script again. Resources already created are detected and reused.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Done, ready, or nothing to do | Continue with the next step |
| 1 | A component failed, or something is missing or not usable | Read the message; the script that fixes it is named |
| 2 | Invalid parameter or configuration (no region, bad config, missing e-mail with `-NonInteractive`) | Fix the config or pass the parameter |
| 3 | A permission is missing | The message names the service, the denied action and the exact managed policy or template. Fix it and run the same script again |
| 4 | A step precondition is not met | See below |

Exit code 4 means: the application log group does not exist (run `ops/aws/ec2/deploy.ps1`), the e-mail subscription is `PendingConfirmation`, the attack evidence file is missing (run the attack), or the CloudTrail quota is reached. In `full-teardown.ps1` and `verify-zero-cost.ps1`, 4 means the manifest cannot be read, and `full-teardown.ps1` also uses 5 for a cancelled run or a deletion blocked by S3 Object Lock retention.

## Permissions needed before you start

An IAM user can have at most 10 managed policies attached directly, and the services below need more than that. Use the lab IAM group (`sangyshop-lab-group`) instead of direct attachments. If you attach a policy to a user and hit `LimitExceeded`, the script stops with exit code 3 and points to the group.

Each script header lists its exact IAM actions in a `Required IAM actions:` block.

### Required permissions

| Service | IAM prefix | AWS managed policy | Used for |
|---|---|---|---|
| ec2 | ec2 | AmazonEC2FullAccess | Network, AMI and flow logs of EC2. |
| s3 | s3 | AmazonS3FullAccess | Application bucket and trail bucket. |
| s3api | s3 | AmazonS3FullAccess | Application bucket and trail bucket. |
| rds | rds | AmazonRDSFullAccess | Lab database. |
| logs | logs | CloudWatchLogsFullAccess | Log groups and metric filter. |
| cloudwatch | cloudwatch | CloudWatchFullAccessV2 | Alarms. |
| sns | sns | AmazonSNSFullAccess | Topic and subscription. |
| cloudtrail | cloudtrail | AWSCloudTrail_FullAccess | Trail. |
| guardduty | guardduty | AmazonGuardDutyFullAccess_v2 | Detector. |
| events | events | AmazonEventBridgeFullAccess | Rule of the blocker. |
| lambda | lambda | AWSLambda_FullAccess | Function of the blocker. |
| ssm | ssm | `AmazonSSMReadOnlyAccess` (Get, Describe, List), `AmazonSSMFullAccess` (SendCommand and other writes) | Read actions only need the read only policy. `SendCommand` (used by `plant-leaked-credential.ps1`) is not in it: apply `lab-core.json` with `ops/aws/iam/ensure-lab-group.ps1` (preferred) or attach `AmazonSSMFullAccess`. The lab has an AMI fallback that works without SSM reads. |
| secretsmanager | secretsmanager | SecretsManagerReadWrite | Database secret. |
| kms | kms | AWSKeyManagementServicePowerUser | Keys used by RDS and secrets. |
| iam | iam | none (use `lab-iam-scoped.json`) | No managed policy fits without excess. Use `lab-iam-scoped.json` from the lab group (`ops/aws/iam/lab-iam-scoped.json`). |
| resourcegroupstaggingapi | tag | none (use `lab-core.json`) | No managed policy needed beyond `lab-core.json` (tag and identity reads). |
| sts | sts | none (use `lab-core.json`) | No managed policy needed beyond `lab-core.json` (tag and identity reads). |

### Two ways to grant them

1. Scoped templates (recommended). `ops/aws/iam/ensure-lab-group.ps1` creates or updates `sangyshop-lab-group` from three least-privilege templates in `ops/aws/iam/policies/`: `lab-core.json`, `lab-detection.json` and `lab-iam-scoped.json`. That is 3 attachments, well under the quota of 10 per group. Review first with `-WhatIf`, then run it, then add yourself explicitly:

   ```powershell
   ./ops/aws/iam/ensure-lab-group.ps1 -WhatIf
   ./ops/aws/iam/ensure-lab-group.ps1
   ./ops/aws/iam/ensure-lab-group.ps1 -AddUser <your-iam-user>
   ```

2. Managed policies by hand. The table lists 13 distinct AWS managed policies, plus `lab-iam-scoped.json` for IAM, which is 14 attachments. That is above the quota of 10 per group and of 10 per user, so it needs at least two holders, for example two IAM groups. Prefer the scoped templates.

The tool only touches the lab group, only adds permissions, and never reads or changes other groups. See `ops/aws/iam/README.md`.

## Cost

The detection components are billable: CloudTrail data events, CloudWatch Logs ingestion, VPC flow logs, GuardDuty and the S3 bucket for trail logs. Use `-SkipFlowLogs`, `-SkipGuardDuty` and `-SkipDataEvents` to reduce the cost, and tear down when you finish.

## Teardown

```powershell
./ops/aws/ir-lab/detection/disable-all.ps1 -WhatIf     # detection stack only (-KeepLogs keeps logs and trail bucket)
./ops/aws/ir-lab/full-teardown.ps1 -Region us-east-1 -WhatIf
./ops/aws/ir-lab/full-teardown.ps1 -Region us-east-1
./ops/aws/ir-lab/verify-zero-cost.ps1 -Region us-east-1
```

`full-teardown.ps1` finds resources by the lab tag and by the manifest, not by names you type. It removes, in reverse dependency order: block entries, the blocker, the detection stack, the deployment (it runs `ops/aws/ec2/teardown.ps1`), evidence snapshots and bucket (`-PreserveEvidence` keeps them), and the leaked credential last. A resource with neither the tag nor a manifest entry is listed as unmarked and left unchanged. Failures never stop independent steps, and a final sweep retries what is left. It is idempotent. Options: `-RunId`, `-AllRuns`, `-NonInteractive`, `-ManifestPath`.

`verify-zero-cost.ps1` is read-only. It prints `nothing billable remaining` and exits 0, or lists what remains and exits 1. If a query fails, the answer is inconclusive (exit 1); it never claims a clean account when it could not look. `-Json` prints one JSON document.

## Safety

- Run with `-WhatIf` first. It prints every planned call and changes nothing.
- The scripts never attach policies, create IAM policies or add users to groups. Only `ops/aws/iam/ensure-lab-group.ps1` touches the lab group, and only on request.
- A resource without the lab tag is never modified or deleted.
- The leaked credential is a separate low-privilege identity, never your own. Use it only in an isolated lab account.
- Secrets are never printed; the built-in masker hides them.
