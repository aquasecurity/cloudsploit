var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Excessive Security Groups',
	category: 'EC2',
	description: 'Determine if there are an excessive number of security groups in the account',
	more_info: 'Keeping the number of security groups to a minimum helps reduce the attack surface of an account. Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
	recommended_action: 'Limit the number of security groups to prevent accidental authorizations',
	apis: ['EC2:describeSecurityGroups'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){

			var describeSecurityGroups = helpers.addSource(cache, source,
				['ec2', 'describeSecurityGroups', region]);
			
			if (!describeSecurityGroups) return rcb();

			if (describeSecurityGroups.err || !describeSecurityGroups.data) {
				helpers.addResult(results, 3,
					'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
				return rcb();
			}

			if (!describeSecurityGroups.data.length) {
				helpers.addResult(results, 0, 'No security groups present', region);
				return rcb();
			}

			var returnMsg = ' number of security groups: ' + describeSecurityGroups.data.length + ' groups present';

			if (describeSecurityGroups.data.length > 40) {
				helpers.addResult(results, 2, 'Excessive' + returnMsg, region);
			} else if (describeSecurityGroups.data.length > 30) {
				helpers.addResult(results, 1, 'Large' + returnMsg, region);
			} else {
				helpers.addResult(results, 0, 'Acceptable' + returnMsg, region);
			}

			rcb();
			
		}, function(){
			callback(null, results, source);
		});
	}
};
