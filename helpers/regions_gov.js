// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
	'us-gov-west-1'
];

module.exports = {
	all: regions,
	acm: regions,
	cloudfront: [],
	autoscaling: regions,
	iam: regions,
	route53: [],
	route53domains: [],
	s3: regions,
	cloudtrail: regions,
	cloudwatchlogs: regions,
	configservice: regions,
	ec2: regions,
	elb: regions,
	elbv2: regions,
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
	ses: [],
	sns: regions,
	sqs: regions,
	// SSE via KMS is only supported in some regions
	// even though SQS is supported in all regions.
	sqs_encrypted: regions,
	sts: regions,
	lambda: regions,
	directconnect: regions,
	directoryservice: []
};
