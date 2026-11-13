# Lab IAM group

This folder holds the permission templates for the AWS lab and the helper that applies them.

## Why a group

An IAM user can have at most 10 managed policies attached directly. The AWS managed policies the lab services need (EC2, RDS, S3, Secrets Manager, CloudTrail, GuardDuty, SNS, CloudWatch Logs, and others) add up to more than that. Attaching the policies to a group avoids the limit, because a group has its own quota of 10 managed policies and the user inherits them.

The group is named `sangyshop-lab-group`. Only names that match `sangyshop-lab-*` are accepted by the tooling.

## Policy templates

The three documents in `policies/` replace broad managed policies with least-privilege ones. Each stays under the 6144 character limit for managed policies (white space excluded).

| File | Covers |
|---|---|
| `lab-core.json` | EC2 and VPC, RDS, S3 buckets named `sangyshop-*`, Secrets Manager secrets named `sangyshop*`, application log groups under `/sangyshop/`, SSM |
| `lab-detection.json` | CloudTrail, GuardDuty, SNS, CloudWatch alarms and log metric filters, EventBridge, the blocker Lambda, VPC flow logs |
| `lab-iam-scoped.json` | IAM roles, instance profiles, users and policies, limited to names starting with `sangyshop-` |

Placeholders `${AccountId}` and `${Region}` are replaced when a template is rendered. No account id is stored in the repository.

Safety properties of the templates:

- IAM write actions apply only to resources whose names start with `sangyshop-`.
- `iam:PassRole` is limited to `sangyshop-*` roles and to the EC2, Lambda and VPC flow logs services.
- `iam:AttachRolePolicy` is limited to `AmazonSSMManagedInstanceCore` and to `sangyshop-*` policies.
- Destructive sweep actions on resources that cannot be named in advance require the tag `lab=sangyshop-lab-aws`.
- No template grants permission to create or attach policies to users or groups.

Together the three templates use 3 of the 10 managed policy slots of the group.

## Applying the templates

Run from the repository root:

```powershell
./ops/aws/iam/ensure-lab-group.ps1 -WhatIf     # show what would change
./ops/aws/iam/ensure-lab-group.ps1             # create or update the group and its policies
./ops/aws/iam/ensure-lab-group.ps1 -AddUser <your-iam-user>
```

Adding a user to the group is always explicit.

## What the tooling does not do

- It never reads or changes any group other than the lab group.
- It only adds permissions to the lab group. It does not remove permissions from users, roles or other groups.
- The lab scripts never grant themselves IAM permissions. If a permission is missing, a script stops with exit code 3 and names the action.
- It does not run any lab script and calls only IAM, plus the identity lookup `sts get-caller-identity`, which needs no permission.

## Checking coverage

`LabGroup-Common.ps1` contains `Get-RequiredActions`, which scans the lab scripts for AWS CLI calls and lists the IAM actions they need. Compare its output with the actions in the rendered templates after any script change.
