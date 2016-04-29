var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Excessive Security Groups',
	category: 'EC2',
	description: 'Determine if there are an excessive number of security groups in the account',
	more_info: 'Keeping the number of security groups to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Limit the number of security groups to prevent accidental authorizations',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.each(helpers.regions.ec2, function(region, rcb){
			var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));

			// Update the region
			LocalAWSConfig.region = region;
			var ec2 = new AWS.EC2(LocalAWSConfig);

			// Get the account attributes
			helpers.cache(cache, ec2, 'describeSecurityGroups', function(err, data) {
				if (err || !data || !data.SecurityGroups) {
					results.push({
						status: 3,
						message: 'Unable to query for security groups',
						region: region
					});

					return rcb();
				}

				if (!data.SecurityGroups.length) {
					results.push({
						status: 0,
						message: 'No security groups present',
						region: region
					});

					return rcb();
				}

				if (data.SecurityGroups.length > 40) {
					results.push({
						status: 2,
						message: 'Excessive number of security groups: ' + data.SecurityGroups.length + ' groups present',
						region: region
					});
				} else if (data.SecurityGroups.length > 30) {
					results.push({
						status: 1,
						message: 'Large number of security groups: ' + data.SecurityGroups.length + ' groups present',
						region: region
					});
				} else {
					results.push({
						status: 0,
						message: 'Acceptable number of security groups: ' + data.SecurityGroups.length + ' groups present',
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
