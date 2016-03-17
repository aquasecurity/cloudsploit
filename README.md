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
To begin using the scanner, edit the index.js file with your AWS key, secret, and optionally (for temporary credentials), a session token. You can also set a file containing credentials or load them via environment variables. To determine the permissions associated with your credentials, see the [permissions section below](#permissions). In the list of plugins, comment out any plugins you do not wish to run. Then save and run ```node index.js```. 

### Cross Account Roles
When using the [hosted scanner](https://cloudsploit.com/scan), you'll need to create a cross-account IAM role. Cross-account roles enable you to share access to your account with another AWS account using the same policy model that you're used to. The advantage is that cross-account roles are much more secure than key-based access, since an attacker who steals a cross-account role ARN still can't make API calls unless they also infiltrate the authorized AWS account.

To create a cross-account role:

1. Navigate to the [IAM console](https://console.aws.amazon.com/iam/home).
2. Click "Roles" and then "Create New Role".
3. Provide a role name (suggested "cloudsploit").
4. Select the "Role for Cross-Account Access" radio button.
5. Click the "Select" button next to "Allows IAM users from a 3rd party AWS account to access this account."
6. Enter `057012691312` for the account ID (this is the ID of CloudSploit's AWS account).
7. Copy the auto-generated external ID from the CloudSploit web page and paste it into the AWS IAM console textbox.
8. Ensure that "Require MFA" is _not_ selected.
9. Click "Next Step".
10. Select the "Security Audit" policy. Then click "Next Step" again.
11. Click on your new role.
12. Expand "Inline Policies" and click on the link to create a new one.
13. Select "Custom Policy".
14. Provide any policy name, and then copy the entire [permissions document](#permissions) below into the box.
15. Click "Apply Policy".

## Permissions
The scans require read-only permissions to your account. This can be done by adding the "Security Audit" AWS managed policy to your IAM user or role, as well as the "cloudtrail:DescribeTrails" permission (can be created via an inline permissions document).

### Security Audit Managed Policy (Recommended)

To configure the managed policy:

1. Open the [IAM Console](https://console.aws.amazon.com/iam/home).
2. Find your user or role.
3. Click the "Permissions" tab.
4. Under "Managed Policy", click "Attach policy".
5. In the filter box, enter "Security Audit"
6. Select the "Security Audit" policy and save.

### Inline Policy (Not Recommended)

If you'd prefer to be more restrictive, the following IAM policy contains the exact permissions used by the scan.

WARNING: This policy will likely change as more plugins are written. If a test returns "UNKNOWN" it is likely missing a required permission. The preferred method is to use the "Security Audit" policy.

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
            "cloudtrail:DescribeTrails",
            "s3:GetBucketVersioning",
            "s3:ListAllMyBuckets",
            "s3:GetBucketAcl",
            "ec2:DescribeAccountAttributes",
            "ec2:DescribeAddresses",
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "iam:ListServerCertificates",
            "iam:GetAccountPasswordPolicy",
            "iam:GetAccountSummary",
            "iam:GetAccessKeyLastUsed",
            "iam:GetGroup",
            "iam:ListMFADevices",
            "iam:ListUsers",
            "iam:ListGroups",
            "iam:ListAccessKeys",
            "iam:ListVirtualMFADevices",
            "elasticloadbalancing:DescribeLoadBalancerPolicies",
            "elasticloadbalancing:DescribeLoadBalancers",
            "route53domains:ListDomains",
            "rds:describeDBInstances"
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
  * ```description``` (string): a description of what the plugin does
  * ```tests``` (map): an object containing tests that should be run. Each test should have:
    * ```title``` (string): a test-level title
    * ```description``` (string): a test-level description of what the test does
    * ```more_info``` (string): a more detailed description of the risk being tested for
    * ```link``` (string): an AWS help URL describing the service or risk, preferably with mitigation methods
    * ```recommended_action``` (string): what the user should do to mitigate the risk found
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
* Use async.eachLimit to reduce the number of simultaneous API calls. Instead of using a for loop on 100 requests, spread them out using async's each limit.

## Running Scans via Lambda

CloudSploit can be run as a Lambda function within your account. To set this up, you must create a role for your function with the necessary privileges, then configure it to run via an invocation or schedule.

### Configure a Lambda Role

Lambda functions need an IAM role which they can assume. Create a new role for Lambda within the IAM console. Then, apply the following managed policies:

* Security Audit
* AWSLambdaBasicExecutionRole

### Create a New Function

1. Open the Lambda console and create a new Lambda function.
2. Enter a name and description for the function.
3. Give it at least 256 MB of memory and a 3-5 minute timeout (if your account uses few services, you can select a lower timeout).
4. For "Handler", enter "lambda.handler"
5. For "Role", select the role you created previously.
6. You do not need to run from within a VPC, but you can select those options if you'd like.
7. Within this cloned repository on your local machine, navigate to the root directory and ZIP all the contents. If you extracted the ZIP, `lambda.js` should be at the top level. (Do not ZIP the repository's folder, ZIP its contents).
8. Upload the ZIP to the Lambda console.
9. Save your function.

### Testing the Function

The Lambda function expects the event object to contain a series of plugin query names which it should run. If none are provided, it will respond with the list of all available plugins. To test this, configure a test event within the Lambda console and enter `{}`. Save and then test. You should see a response like the following:

```
{
  "code": 0,
  "data": [
    {
      "title": "CloudTrail Bucket Delete Policy",
      "query": "cloudtrailBucketDelete",
      "description": "Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token"
    },
    {
      "title": "CloudTrail Enabled",
      "query": "cloudtrailEnabled",
      "description": "Ensures CloudTrail is enabled for all regions within an account"
    },
...
}
```

This response shows all of the available plugins which can be run. Note the "query" property. Next, configure the test event with the following: 

```
{
  "plugins": [
    "cloudtrailEnabled"
  ]
}
```

Run the test again, and you should now see results for the scan:

```
{
  "code": 0,
  "data": [
    {
      "title": "CloudTrail Enabled",
      "query": "cloudtrailEnabled",
      "category": "CloudTrail",
      "description": "Ensures CloudTrail is enabled for all regions within an account",
      "tests": {
        "cloudtrailEnabled": {
          "title": "CloudTrail Enabled",
          "description": "Ensures CloudTrail is enabled for all regions within an account",
          "more_info": "CloudTrail should be enabled for all regions in order to detect suspicious activity in regions that are not typically used.",
          "link": "http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html",
          "recommended_action": "Enable CloudTrail for all regions and ensure that at least one region monitors global service events",
          "results": [
            {
              "status": 2,
              "message": "CloudTrail is not enabled",
              "region": "us-east-1"
            },
            ...
          }
        }
      }
    }
  ]
}
```

You will have results for each region. You can then run additional tests by modifying the value of "plugins" in the `event.plugins` test object. You can include as many plugins in each test as you'd like.

### Running all Plugins

To run all plugins at once, simply invoke the Lambda function with the following event object:

```
{
  "plugins": []
}
```

### Next Steps

You can now schedule your function to run periodically, send you emails with results, or perform any number of actions based on the results of a scan.