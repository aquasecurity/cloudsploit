var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

// Default limits to override
var limits = {
	'max-elastic-ips': 5
};

module.exports = {
	title: 'Elastic IP Limit',
	category: 'EC2',
	description: 'Determine if the number of allocated EIPs is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
	recommended_action: 'Contact AWS support to increase the number of EIPs available',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',

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
				
				helpers.cache(cache, ec2, 'describeAddresses', function(err, data) {
					if (err || !data || !data.Addresses) {
						results.push({
							status: 3,
							message: 'Unable to describe addresses for Elastic IP limit',
							region: region
						});

						return rcb();
					}

					if (!data.Addresses.length) {
						results.push({
							status: 0,
							message: 'No Elastic IPs found',
							region: region
						});

						return rcb();
					}

					// If EIPs exist, determine type of each
					var eips = 0;

					for (i in data.Addresses) {
						if (data.Addresses[i].Domain !== 'vpc') { eips++; }
					}

					var returnMsg = {
						status: 0,
						message: 'Account contains ' + eips + ' of ' + limits['max-elastic-ips'] + ' available Elastic IPs',
						region: region
					};

					if (eips === 0) {
						returnMsg.message = 'No Elastic IPs found';
					} else if (eips === limits['max-elastic-ips'] - 1) {
						returnMsg.status = 1;
					} else if (eips >= limits['max-elastic-ips']) {
						returnMsg.status = 2;
					}

					results.push(returnMsg);
					
					rcb();
				});
			});
		}, function(){
			return callback(null, results);
		});
	}
};