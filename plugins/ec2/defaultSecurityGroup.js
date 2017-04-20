var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Default Security Group',
	category: 'EC2',
	description: 'Ensure the default security groups block all traffic by default',
	more_info: 'The default security group is often used for resources launched without a defined security group. For this reason, the default rules should be to block all traffic to prevent an accidental exposure.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group',
	recommended_action: 'Update the rules for the default security group to deny all traffic by default',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){
			var describeSecurityGroups = helpers.addSource(cache, source,
				['ec2', 'describeSecurityGroups', region]);

			if (!describeSecurityGroups) return rcb();

			if (describeSecurityGroups.err || !describeSecurityGroups.data) {
				helpers.addResult(results, 3, 'Unable to query for security groups', region);
				return rcb();
			}

			if (!describeSecurityGroups.data.length) {
				helpers.addResult(results, 0, 'No security groups present', region);
				return rcb();
			}

			for (s in describeSecurityGroups.data) {
				var sg = describeSecurityGroups.data[s];

				if (sg.GroupName === 'default') {
					if (sg.IpPermissions.length ||
					 	sg.IpPermissionsEgress.length) {
						helpers.addResult(results, 2,
							'Default security group has ' + sg.IpPermissions.length + ' inbound and ' + sg.IpPermissionsEgress.length + ' outbound rules',
							region, sg.GroupId);
					} else {
						helpers.addResult(results, 0,
							'Default security group does not have inbound or outbound rules',
							region, sg.GroupId);
					}
				}
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
