var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Instance Limit',
	category: 'EC2',
	description: 'Determine if the number of EC2 instances is close to the AWS per-account limit',
	more_info: 'AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit',
	recommended_action: 'Contact AWS support to increase the number of instances available',
	apis: ['EC2:describeAccountAttributes', 'EC2:describeInstances'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){
			var describeAccountAttributes = helpers.addSource(cache, source,
				['ec2', 'describeAccountAttributes', region]);

			if (!describeAccountAttributes) return rcb();

			if (describeAccountAttributes.err || !describeAccountAttributes.data) {
				helpers.addResult(results, 3,
					'Unable to query for account limits: ' + helpers.addError(describeAccountAttributes), region);
				return rcb();
			}

			var limits = {
				'max-instances': 20
			};

			// Loop through response to assign custom limits
			for (i in describeAccountAttributes.data) {
				if (limits[describeAccountAttributes.data[i].AttributeName]) {
					limits[describeAccountAttributes.data[i].AttributeName] = describeAccountAttributes.data[i].AttributeValues[0].AttributeValue;
				}
			}

			var describeInstances = helpers.addSource(cache, source,
				['ec2', 'describeInstances', region]);

			if (!describeInstances) return rcb();

			if (describeInstances.err || !describeInstances.data) {
				helpers.addResult(results, 3,
					'Unable to query for instances: ' + helpers.addError(describeInstances), region);
				return rcb();
			}
			
			if (!describeInstances.data.length) {
				helpers.addResult(results, 0, 'No instances found', region);
				return rcb();
			}

			var percentage = Math.ceil((describeInstances.data.length / limits['max-instances'])*100);
			var returnMsg = 'Account contains ' + describeInstances.data.length + ' of ' + limits['max-instances'] + ' (' + percentage + '%) available instances';

			if (percentage >= 90) {
				helpers.addResult(results, 2, returnMsg, region);
			} else if (percentage >= 75) {
				helpers.addResult(results, 1, returnMsg, region);
			} else {
				helpers.addResult(results, 0, returnMsg, region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};