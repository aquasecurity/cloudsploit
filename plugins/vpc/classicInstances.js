var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Detect EC2 Classic Instances',
	category: 'VPC',
	description: 'Ensures AWS VPC is being used for instances instead of EC2 Classic',
	more_info: 'VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.',
	link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html',
	recommended_action: 'Migrate instances from EC2 Classic to VPC',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		var params = {
			Filters: [
				{
					Name: 'instance-state-name',
					Values: [
						'pending',
						'running',
						'shutting-down',
						'stopping',
						'stopped'
					]
				}
			]
		};

		async.each(helpers.regions.vpc, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			helpers.cache(cache, ec2, 'describeInstances', function(err, data) {
				if (err || !data || !data.Reservations) {
					results.push({
						status: 3,
						message: 'Unable to query for instances',
						region: region
					});

					return rcb();
				}

				// Perform checks for establishing if MFA token is enabled
				if (!data.Reservations.length) {
					results.push({
						status: 0,
						message: 'No instances found',
						region: region
					});

					return rcb();
				}

				var inVpc = 0;
				var notInVpc = 0;

				for (i in data.Reservations) {
					for (j in data.Reservations[i].Instances) {
						if (!data.Reservations[i].Instances[j].NetworkInterfaces || !data.Reservations[i].Instances[j].NetworkInterfaces.length) {
							// Network interfaces are only listed when the instance is in a VPC
							// Not having interfaces indicates the instance is in classic
							notInVpc+=1;
						} else {
							inVpc+=1;
						}
					}
				}

				if (notInVpc) {
					results.push({
						status: 1,
						message: 'There are ' + notInVpc + ' instances in EC2-Classic',
						region: region
					});
				} else if (inVpc) {
					results.push({
						status: 0,
						message: 'There are ' + inVpc + ' instances in a VPC',
						region: region
					});
				} else {
					results.push({
						status: 0,
						message: 'No instances found',
						region: region
					});
				}

				rcb();
			});
		}, function(){
			callback(null, results);
		});
	}
};
