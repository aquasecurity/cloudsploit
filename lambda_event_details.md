# Expected Event Information:
There are three ways to invoke the lambda.
1. Publish event to SNS topic that the lambda is subscribed to.
2. Setup a CloudWatch Event. The Event must be in the details section.
3. Directly invoke the lambda with the event as the payload

### Important Notes
* If neither SNS nor Cloudwatch events are identified, it is assumed to be a direct invocation.
* The accepted format for a payload is that it must contain exactly one of a supported service and additionally any other information in an additional settings object.
* The supprted services are: `aws`, `gcp`, `github`, `oracle`, `azure`
* Any other service other than `aws` requires that secrets be passed in through `AWS secretmanager`, however you can put as much of the configuration for the service as you would like into `secretsmanager`.
* If a service contains a key for something that is required to be a secret, the scan will fail.
* Any information found in `secretsmanager` will be added directly to the configuration object and the` credentialID` value will be deleted. Examples of minimum expected values in secrets Manager can be found in the examples below.

## AWS
The aws event accepts either a full role arn or an account ID for which it can find the provided default_role set in the environment variables.

NOTE: If both `accountId` and `roleArn` are present, it will use the `accountId` and the role name from the cloudformation parameter and overwrite the `roleArn` value.

Example events:

```
{
  aws: {
    accountId: 1234567890,
    externalId: '' // optional
  },
  settings: {...},
  "s3Prefix": "PREFIX_FOR_FINDINGS_FROM_THIS_SPECIFIC_INVOCATION"
}
```
or
```
{
  aws: {
    roleArn: "arn:aws:iam::1234567890:role/someRole",
    externalId: '' // optional
  },
  settings: {...}
}
```
## GCP
Required credential information cannot be passed in through the payload and must be passed in through SecretesManager. The last part of the key provided in a field 'credentialId'

Example event:
```
{
  gcp: {
    credentialId: 'some_key_string',
    project: '',
    serviceId:'',
    region:''
  },
  settings: {...}
}
```

Minimum Required information in SecretsManager:
```
{
  "KeyValue": "value"
}
```

## Oracle
Required credential information cannot be passed in through the payload and must be passed in through SecretesManager. The last part of the key provided in a field 'credentialId'

Example event:
```
{
  oracle: {
    credentialId: 'some_key_string'
    RESTversion: '',
    tenancyId: '',
    compartmentId: '',
    userId:  '',
    region: ''
  },
  settings: {...}
}
```

Minimum Required information in SecretsManager:
```
{
  "private_key": "value"
}
```

## Github
Required credential information cannot be passed in through the payload and must be passed in through SecretesManager. The last part of the key provided in a field 'credentialId'

Example event:
```
{
  github: {
    credentialId: 'some_key_string'
    url: '',
    organization: '',
    login: ''
  },
  settings: {...}
}
```

Minimum Required information in SecretsManager:
```
{
  "token": "value"
}
```

## Azure
Required credential information cannot be passed in through the payload and must be passed in through SecretesManager. The last part of the key provided in a field 'credentialId'

Example event:
```
{
  azure: {
    credentialId: 'some_key_string'
    DirectoryID: '',
    SubscriptionID: '',
    location: ''
  },
  settings: {...}
}
```

Minimum Required information in SecretsManager:
```
{
  "keyValue": "value",
  "keyFingerprint" : "value"
}
```

# S3 Output
Two objects are created the S3 bucket specified in the template parameters. The format for the object keys are:
```
s3://<BucketName>/<BucketPrefix>/<s3Prefix>/<date>.json
s3://<BucketName>/<BucketPrefix>/<s3Prefix>/latest.json
```

Where:
* BucketName: Required parameter passed in through Cloudformation via the Lambda environment variables.
* BucketPrefix: Optional parameter passed in through Cloudformation via the Lambda environment variables.
* s3Prefix: Optional value passed in through the event invokation at root (an example provided below.)
* date: Date is generated based on the day of the run.

Example Event with s3Prefix:
```
{
  aws: {
    accountId: 1234567890,
    externalId: '' // optional
  },
  settings: {...},
  s3Prefix: "My/File/Prefix"
}
```
