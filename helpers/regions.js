var regions = [
	'us-east-1',		// Northern Virginia
	'us-east-2',		// US East (Ohio)
	'us-west-1',		// Northern California
	'us-west-2',		// Oregon
	'ap-northeast-1',	// Asia Pacific (Tokyo)
	'ap-northeast-2',	// Asia Pacific (Seoul)
	'ap-southeast-1',	// Asia Pacific (Singapore)
	'ap-southeast-2',	// Asia Pacific (Sydney)
	'eu-central-1',		// EU (Frankfurt)
	'eu-west-1',		// EU (Ireland)
	'sa-east-1',		// South America (São Paulo)
	'ap-south-1'		// Mumbai
];

module.exports = {
	all: regions,
	cloudtrail: regions,
	configservice: regions,
	ec2: regions,
	elb: regions,
	kms: regions,
	vpc: regions,
	rds: regions,
	apigateway: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'],
	cloudwatch: regions,
	dynamodb: regions,
	ecr: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1'],
	ecs: ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2'],
	ses: ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1'],
	flowlogs: ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1', 'ap-southeast-2', 'ap-southeast-1', 'eu-west-1', 'eu-central-1']
};
