# CloudSploit for Huawei Cloud

## Create IAM Policy for Security Scanning

1. Log into your Huawei Cloud Console and navigate to **Identity and Access Management (IAM)**.
2. Go to **Policies** under **Permissions** and click **Create Custom Policy**.
3. Set the **Policy Name** to `CloudSploitSecurityAudit` and choose **JSON** as the policy configuration mode.
4. Copy and paste the following JSON code into the policy editor. This policy grants read-only permissions for CloudSploit to scan Huawei Cloud resources, including Kubernetes, disks, bandwidth, Elastic IPs, clusters, nodes, and keys. *Note*: Adjust the resource scope based on your tenant or project requirements.

{ "Version": "1.1", "Statement": \[ { "Effect": "Allow", "Action": \[ "ecs:servers:list", "ecs:servers:get", "ecs:securityGroups:list", "ecs:securityGroups:get", "ecs:flavors:list", "ecs:volumes:list", "ecs:volumes:get", "ecs:disks:list", "ecs:disks:get", "ecs:networkInterfaces:list", "ecs:keypairs:list", "ecs:publicIps:list", "ecs:bandwidths:list", "ecs:bandwidths:get", "ecs:eips:list", "ecs:eips:get", "vpc:vpcs:list", "vpc:vpcs:get", "vpc:subnets:list", "vpc:subnets:get", "vpc:securityGroups:list", "vpc:securityGroups:get", "vpc:routes:list", "vpc:bandwidths:list", "vpc:bandwidths:get", "iam:users:list", "iam:roles:list", "iam:groups:list", "iam:policies:list", "iam:permissions:get", "rds:instances:list", "rds:instances:get", "rds:backups:list", "rds:parameters:get", "obs:buckets:list", "obs:buckets:get", "obs:objects:list", "obs:policies:get", "kms:keys:list", "kms:keys:get", "kms:aliases:list", "waf:domains:list", "waf:policies:list", "waf:certificates:list", "elb:loadbalancers:list", "elb:loadbalancers:get", "elb:certificates:list", "elb:healthmonitors:list", "cce:clusters:list", "cce:clusters:get", "cce:nodes:list", "cce:nodes:get", "cce:nodePools:list", "cce:nodePools:get", "cce:jobs:list", "nat:gateways:list", "nat:gateways:get", "nat:snatRules:list", "nat:dnatRules:list", "dns:zones:list", "dns:recordsets:list", "hss:hosts:list", "hss:vulnerabilities:get", "antiddos:resources:list", "antiddos:configurations:get" \], "Resource": \["\*"\] } \] }

5. Click **OK** to save the custom policy.

## Create IAM User for CloudSploit

1. In the Huawei Cloud Console, navigate to **Identity and Access Management (IAM)** &gt; **Users**.
2. Click **Create User**.
3. Set the **User Name** to `CloudSploitScanner` and select **Programmatic Access** as the access type.
4. Under **User Groups**, assign the user to a group or directly attach the `CloudSploitSecurityAudit` policy under **Permissions**.
   - If creating a new group, name it `CloudSploitAccessGroup`, and attach the `CloudSploitSecurityAudit` policy to the group.
5. Complete the user creation process by clicking **Create**.
6. After creation, go to **Security Credentials** for the `CloudSploitScanner` user and click **Create Access Key**.
7. Download the **Access Key ID** and **Secret Access Key** (CSV file). Save these securely, as they will not be displayed again.
8. Use the **Access Key ID** and **Secret Access Key** to configure CloudSploit for Huawei Cloud scanning. Refer to CloudSploit’s documentation to input these credentials (e.g., in a `config.js` file or environment variables).

## Notes

- The updated permissions include actions for **Kubernetes (CCE)** (`cce:clusters:list`, `cce:nodes:list`, `cce:nodePools:list`), **disks** (`ecs:disks:list`), **bandwidth** (`ecs:bandwidths:list`, `vpc:bandwidths:list`), **Elastic IPs** (`ecs:eips:list`), **clusters** and **nodes** (`cce:clusters:get`, `cce:nodes:get`), and **keys** (`kms:keys:list`, `ecs:keypairs:list`).
- These permissions cover key Huawei Cloud services for CSPM scanning. Adjust the policy if you need to scan additional services or restrict access to specific resources.
- Ensure the Huawei Cloud region and tenant ID are correctly configured in CloudSploit to align with the scanned resources.
- Regularly rotate the access keys for security and monitor the `CloudSploitScanner` user’s activity via Huawei Cloud’s **Cloud Trace Service (CTS)**.

- Sample Screenshot when scanning the Huawei cloud

- <img width="682" alt="image" src="https://github.com/user-attachments/assets/f244de78-f459-488d-a441-3f2935a88081" />
