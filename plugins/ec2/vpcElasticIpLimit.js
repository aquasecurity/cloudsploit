var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'VPC Elastic IP Limit',
	category: 'EC2',
	description: 'Determine if the number of allocated VPC EIPs is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
	recommended_action: 'Contact AWS support to increase the number of EIPs available',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',

	run: function(AWSConfig, cache, includeSource, callback) {
		var results = [];
		var source = {};

		async.eachLimit(helpers.regions.ec2, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			// Default limits to override
			var limits = {
				'vpc-max-elastic-ips': 5
			};

			// Get the account attributes
			if (includeSource) source['describeAccountAttributes'] = {};
			if (includeSource) source['describeAddresses'] = {};

			helpers.cache(cache, ec2, 'describeAccountAttributes', function(err, data) {
				if (includeSource) source['describeAccountAttributes'][region] = {error: err, data: data};

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
					if (includeSource) source['describeAddresses'][region] = {error: err, data: data};
					
					if (err || !data || !data.Addresses) {
						results.push({
							status: 3,
							message: 'Unable to describe addresses for VPC Elastic IP limit',
							region: region
						});

						return rcb();
					}

					if (!data.Addresses.length) {
						results.push({
							status: 0,
							message: 'No VPC Elastic IPs found',
							region: region
						});

						return rcb();
					}

					// If EIPs exist, determine type of each
					var eips = 0;

					for (i in data.Addresses) {
						if (data.Addresses[i].Domain === 'vpc') { eips++; }
					}

					var returnMsg = {
						status: 0,
						message: 'Account contains ' + eips + ' of ' + limits['vpc-max-elastic-ips'] + ' available VPC Elastic IPs',
						region: region
					};

					if (eips === 0) {
						returnMsg.message = 'No VPC Elastic IPs found';
					} else if (eips === limits['vpc-max-elastic-ips'] - 1) {
						returnMsg.status = 1;
					} else if (eips >= limits['vpc-max-elastic-ips']) {
						returnMsg.status = 2;
					}

					results.push(returnMsg);
					
					rcb();
				});
			});
		}, function(){
			return callback(null, results, source);
		});
	}
};