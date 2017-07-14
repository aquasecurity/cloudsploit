var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'Instance IAM Role',
	category: 'EC2',
	description: 'Ensures EC2 instances are using an IAM role instead of hard-coded AWS credentials',
	more_info: 'IAM roles should be assigned to all instances to enable them to access AWS resources. Using an IAM role is more secure than hard-coding AWS access keys into application code.',
	link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html',
	recommended_action: 'Attach an IAM role to the EC2 instance',
	apis: ['EC2:describeInstances'],

	run: function(cache, callback) {
		var results = [];
		var source = {};

		async.each(helpers.regions.ec2, function(region, rcb){
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

			var found = 0;

			for (i in describeInstances.data) {
				var accountId = describeInstances.data[i].OwnerId;

				for (j in describeInstances.data[i].Instances) {
					var instance = describeInstances.data[i].Instances[j];

					if (!instance.IamInstanceProfile ||
						!instance.IamInstanceProfile.Arn) {
						found += 1;
						helpers.addResult(results, 2,
							'Instance does not use an IAM role', region,
							'arn:aws:ec2:' + region + ':' + accountId + ':instance/' +
							instance.InstanceId);
					}
				}
			}

			// Too many results to print individually
			if (found > 50) {
				results = [];

				helpers.addResult(results, 2,
					'Over 50 EC2 instances do not use an IAM role', region);
			}

			if (!found) {
				helpers.addResult(results, 0,
					'All ' + describeInstances.data.length + ' instances are using IAM roles', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
