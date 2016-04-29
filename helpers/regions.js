var regions = [
	'us-east-1',		// Northern Virginia
	'us-west-1',		// Northern California
	'us-west-2',		// Oregon
	'ap-northeast-1',	// Asia Pacific (Tokyo)
	'ap-northeast-2',	// Asia Pacific (Seoul)
	'ap-southeast-1',	// Asia Pacific (Singapore)
	'ap-southeast-2',	// Asia Pacific (Sydney)
	'eu-central-1',		// EU (Frankfurt)
	'eu-west-1',		// EU (Ireland)
	'sa-east-1'			// South America (São Paulo)
];

module.exports = {
	all: regions,
	cloudtrail: regions,
	ec2: regions,
	elb: regions,
	kms: regions,
	vpc: regions,
	rds: regions,
	apigateway: ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'],
	cloudwatch: regions,
	dynamodb: regions,
	ecr: ['us-east-1', 'us-west-2', 'eu-west-1'],
	ecs: ['us-east-1', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-southeast-2'],

};