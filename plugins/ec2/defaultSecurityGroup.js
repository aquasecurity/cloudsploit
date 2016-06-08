var AWS = require('aws-sdk');
var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Default Security Group',
	category: 'EC2',
	description: 'Ensure the default security groups block all traffic by default',
	more_info: 'The default security group is often used for resources launched without a defined security group. For this reason, the default rules should be to block all traffic to prevent an accidental exposure.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group',
	recommended_action: 'Update the rules for the default security group to deny all traffic by default',
	cis_benchmark: '4.4',

	run: function(AWSConfig, cache, callback) {
		var results = [];

		async.eachLimit(helpers.regions.ec2, helpers.MAX_REGIONS_AT_A_TIME, function(region, rcb){
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

				for (s in data.SecurityGroups) {
					if (data.SecurityGroups[s].GroupName === 'default') {
						if (data.SecurityGroups[s].IpPermissions.length ||
						 	data.SecurityGroups[s].IpPermissionsEgress.length) {
							results.push({
								status: 2,
								message: 'Default security group has ' + data.SecurityGroups[s].IpPermissions.length + ' inbound and ' + data.SecurityGroups[s].IpPermissionsEgress.length + ' outbound rules',
								region: region,
								resource: data.SecurityGroups[s].GroupId
							});
						} else {
							results.push({
								status: 0,
								message: 'Default security group does not have inbound or outbound rules',
								region: region,
								resource: data.SecurityGroups[s].GroupId
							});
						}
					}
				}

				rcb();
			});
		}, function(){
			callback(null, results);
		});
	}
};
