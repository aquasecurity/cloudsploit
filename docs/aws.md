# CloudSploit For Amazon Web Services (AWS)

## Cloud Provider Configuration
Create a "cloudsploit" user, with the `SecurityAudit` policy.

1. Log into your AWS account as an admin or with permission to create IAM resources.
1. Navigate to the [IAM console](https://console.aws.amazon.com/iam/home).
1. Click on [Users](https://console.aws.amazon.com/iam/home?region=us-east-1#/users) 
1. [Create a new user (Add user)](https://console.aws.amazon.com/iam/home?region=us-east-1#/users$new?step=details)
1. Set the username to `cloudsploit`
1. Set the access type to "Programmatic access", click Next.
1. Select "Attach existing policies directly" and select the SecurityAudit policy.
1. Click "Create policy" to create a supplemental policy (some permissions are not included in SecurityAudit).
1. Click the "JSON" tab and paste the following permission set.
    ```
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ses:DescribeActiveReceiptRuleSet",
                    "athena:GetWorkGroup",
                    "logs:DescribeLogGroups",
                    "logs:DescribeMetricFilters",
                    "elastictranscoder:ListPipelines",
                    "elasticfilesystem:DescribeFileSystems",
                    "servicequotas:ListServiceQuotas"
                ],
                "Resource": "*"
            }
        ]
    }
    ```
1. Click "Review policy."
1. Provide a name (`CloudSploitSupplemental`) and click "Create policy."
1. Return to the "Create user" page and attach the newly-created policy. Click "Next: tags."
1. Set tags as needed and then click on "Create user".
1. Make sure you safely store the Access key ID and Secret access key.
1. Paste them into the corresponding AWS credentials section of the `index.js` file.

If using environment variables, the same ones expected by the aws sdks, namely `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`, can be used.
