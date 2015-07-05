CloudSploit Scans
=================

## Background
CloudSploit scans is an open-source project designed to allow detection of security risks in an AWS account. These scripts are designed to run against an AWS account and return a series of potential misconfigurations and security risks.

## Installation
Ensure that node is installed. If not, install it from [here](https://nodejs.org/download/).

```
git clone git@github.com:cloudsploit/scans.git
```

```
npm install
```

## Setup
To begin using the scanner, edit the index.js file with your AWS key, secret, and optionally (for temporary credentials), a session token. In the list of plugins, comment out any plugins you do not wish to run. Then save and run ```node index.js```.

## Permissions
The scans require read-only permissions to your account. This can be done by adding the following IAM policy to a new user:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "appstream:Get*",
        "autoscaling:Describe*",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResource",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:List*",
        "cloudfront:Get*",
        "cloudfront:List*",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:Describe*",
        "cloudwatch:Get*",
        "cloudwatch:List*",
        "directconnect:Describe*",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "ec2:Describe*",
        "ecs:Describe*",
        "ecs:List*",
        "elasticache:Describe*",
        "elasticbeanstalk:Check*",
        "elasticbeanstalk:Describe*",
        "elasticbeanstalk:List*",
        "elasticbeanstalk:RequestEnvironmentInfo",
        "elasticbeanstalk:RetrieveEnvironmentInfo",
        "elasticloadbalancing:Describe*",
        "elasticmapreduce:Describe*",
        "elasticmapreduce:List*",
        "elastictranscoder:Read*",
        "elastictranscoder:List*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "iam:Get*",
        "kinesis:Describe*",
        "kinesis:Get*",
        "kinesis:List*",
        "opsworks:Describe*",
        "opsworks:Get*",
        "route53:Get*",
        "route53:List*",
        "redshift:Describe*",
        "redshift:ViewQueriesInConsole",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "s3:Get*",
        "s3:List*",
        "sdb:GetAttributes",
        "sdb:List*",
        "sdb:Select*",
        "ses:Get*",
        "ses:List*",
        "sns:Get*",
        "sns:List*",
        "sqs:GetQueueAttributes",
        "sqs:ListQueues",
        "sqs:ReceiveMessage",
        "storagegateway:List*",
        "storagegateway:Describe*",
        "tag:get*",
        "trustedadvisor:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

## Writing a Plugin
Writing a plugin is very simple, but must follow several rules:

* Exports the following:
  * ```title``` (string): a user-friendly title for the plugin
  * ```query``` (string): a camel-case title for the plugin to reference from the index.js file (examplePlugin, sampleTester, etc.)
  * ```category``` (string): the AWS category (EC2, RDS, ELB, etc.)
  * ```aws_service``` (string): the AWS service being tested (IAM, EC2, etc.)
  * ```description``` (string): a description of what the plugin does
  * ```more_info``` (string): a more detailed description of the risk being tested for
  * ```link``` (string): an AWS help URL describing the service or risk, preferably with mitigation methods
  * ```tests``` (map): an object containing tests that should be run. Each test should have:
    * ```title``` (string): a test-level title
    * ```description``` (string): a test-level description of what the test does
    * ```recommendedAction``` (string): what the user should do to mitigate the risk found
    * ```results``` (array): an empty list that will be populated with results of the test
  * ```run``` (function): a function that runs the test (see below)
* Accepts an ```AWSConfig``` object via the run function (AWSConfig contains the access key, secret, region, etc.)
* Calls back with the plugin info containing results for each test

### Result Codes
Each test has a result code that is used to determine if the test was successful and its risk level. The following codes are used:

* 0: OKAY: No risks
* 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
* 2: FAIL: The result presents an immediate risk to the security of the account
* 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)

### Tips for Writing Plugins
* Many security risks can be detected using the same API calls. These risks should be combined as multiple tests under a single plugin in order to minimize the number of API calls being made. For example, two plugins: "s3BucketPolicies" and "s3BucketPreventDelete" both call APIs to list every S3 bucket. These can be combined into a single plugin "s3Buckets" which exports two tests called "bucketPolicies" and "preventDelete". This way, the API is called once, but multiple tests are run on the same results.
* To avoid overwriting the test results when multiple scans are running at once, each plugin should have a function "getPluginInfo" that will return a copy of the plugin's info and tests. This avoids global declaration of the test results.
* Ensure AWS API calls are being used optimally. For example, call describeInstances with empty parameters to get all instances, instead of calling describeInstances multiple times looping through each instance name.