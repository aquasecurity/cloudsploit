// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
	'us-east-1',		// Northern Virginia
	'us-east-2',		// Ohio
	'us-west-1',		// Northern California
	'us-west-2',		// Oregon
	'ca-central-1',		// Canada (Montreal)
	'eu-central-1',		// EU (Frankfurt)
	'eu-west-1',		// EU (Ireland)
	'eu-west-2',		// London
	'eu-west-3',		// Paris
	'ap-northeast-1',	// Asia Pacific (Tokyo)
	'ap-northeast-2',	// Asia Pacific (Seoul)
	'ap-southeast-1',	// Asia Pacific (Singapore)
	'ap-southeast-2',	// Asia Pacific (Sydney)
	'ap-south-1',		// Asia Pacific (Mumbai)
	'sa-east-1'			// South America (São Paulo)
];

module.exports = {
	all: regions,
	acm: regions,
	cloudfront: ['us-east-1'], // CloudFront uses the default global region
	autoscaling: regions,
	iam: ['us-east-1'],
	route53: ['us-east-1'],
	route53domains: ['us-east-1'],
	s3: ['us-east-1'],
	cloudtrail: regions,
	cloudwatchlogs: regions,
	configservice: regions,
	ec2: regions,
	elb: regions,
	elbv2: regions,
	kinesis: regions,
	firehose: regions,
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
	ses: [
		'us-east-1', 'us-west-2',
		'eu-west-1'],
	sns: regions,
	sqs: regions,
	ssm: regions,
	// SSE via KMS is only supported in some regions
	// even though SQS is supported in all regions.
	sqs_encrypted: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1',
					'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2','eu-west-3',
					'ap-northeast-1','ap-northeast-2','ap-northeast-3',
					'ap-southeast-1','ap-southeast-2','ap-south-1','sa-east-1'],
	sts: ['us-east-1'],
	lambda: regions,
	directconnect: regions,
	directoryservice: ['us-east-1', 'us-east-2', 'us-west-2', 'us-west-1', 'ca-central-1',
					   'sa-east-1', 'eu-west-1', 'eu-central-1', 'eu-west-2',
					   'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2', 'ap-northeast-2',
					   'ap-south-1']
};
