// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'cn-north-1',
    'cn-northwest-1'
];

module.exports = {
    all: regions,
    acm: [],
    athena: [],
    cloudfront: [],
    autoscaling: regions,
    iam: ['cn-north-1'],
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
    elb: regions,
    elbv2: regions,
    kinesis: [],
    firehose: regions,
    kms: regions,
    vpc: regions,
    flowlogs: regions,
    rds: regions,
    redshift: regions,
    apigateway: regions,
    cloudwatch: regions,
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
    directoryservice: []
};
