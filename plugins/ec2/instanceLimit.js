var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

// Default limits to override
var limits = {
	'max-instances': 20
};

module.exports = {
	title: 'Instance Limit',
	category: 'EC2',
	description: 'Determine if the number of EC2 instances is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
	recommended_action: 'Contact AWS support to increase the number of instances available',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.each(helpers.regions.ec2, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			// Get the account attributes
			helpers.cache(cache, ec2, 'describeAccountAttributes', function(err, data) {
				if (err || !data || !data.AccountAttributes || !data.AccountAttributes.length) {
					results.push({
						status: 3,
						message: 'Unable to query for account limits',
						region: region
					});

					return rcb();
				}

				// Loop through response to assign custom limits
				for (i in data.AccountAttributes) {
					if (limits[data.AccountAttributes[i].AttributeName]) {
						limits[data.AccountAttributes[i].AttributeName] = data.AccountAttributes[i].AttributeValues[0].AttributeValue;
					}
				}
				
				// Now call APIs to determine actual usage
				helpers.cache(cache, ec2, 'describeInstances', function(err, data) {
					if (err || !data || !data.Reservations) {
						results.push({
							status: 3,
							message: 'Unable to query for instances',
							region: region
						});

						return rcb();
					}

					var returnMsgIl = {
						status: 0,
						message: 'Account contains ' + data.Reservations.length + ' of ' + limits['max-instances'] + ' available instances',
						region: region
					};

					if (data.Reservations.length === limits['max-instances'] - 3) {
						returnMsgIl.status = 1;
					} else if (data.Reservations.length >= limits['max-instances'] - 2) {
						returnMsgIl.status = 2;
					}

					results.push(returnMsgIl);

					rcb();
				});
			});
		}, function(){
			return callback(null, results);
		});
	}
};