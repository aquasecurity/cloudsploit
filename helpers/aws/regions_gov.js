// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'us-gov-west-1',
    'us-gov-east-1'
];

module.exports = {
    default: ['us-gov-west-1'],
    all: regions,
    acm: regions,
    athena: ['us-gov-west-1'],
    cloudfront: [],
    autoscaling: regions,
    iam: regions,
    route53: [],
    route53domains: [],
    s3: regions,
    cloudtrail: regions,
    cloudwatchlogs: regions,
    configservice: regions,
    dynamodb: regions,
    ec2: regions,
    ecr: regions,
    eks: [],
    elastictranscoder: [],
    elb: regions,
    elbv2: regions,
    es: regions,
    kinesis: [],
    firehose: [],
    kms: regions,
    vpc: regions,
    flowlogs: regions,
    rds: regions,
    redshift: regions,
    apigateway: regions,
    cloudwatch: regions,
    dynamodb: regions,
    ecr: regions,
    ecs: regions,
    sagemaker: [],
    ses: [],
    sns: regions,
    sqs: regions,
    ssm: regions,
    // SSE via KMS is only supported in some regions
    // even though SQS is supported in all regions.
    sqs_encrypted: regions,
    sts: regions,
    transfer: [],
    lambda: regions,
    directconnect: regions,
    directoryservice: [],
    workspaces: ['us-gov-west-1']
};
