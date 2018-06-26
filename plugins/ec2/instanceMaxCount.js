var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'EC2 Max Instances',
	category: 'EC2',
	description: 'Checks for the number of running instances in an account and triggers a failing result if it exceeds a certain count',
	more_info: 'Checks for the number of running instances in an account and triggers a failing result if it exceeds a certain count',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
	recommended_action: 'Checks for the number of running instances in an account and triggers a failing result if it exceeds a certain count',
	apis: ['EC2:describeInstances'],
	settings: {
		instance_count_threshold: {
			name: 'Instance Count Threshold',
			description: 'If more than this number of instances are running ',
			regex: '^[1-2]{1}[0-9]{0,2}$',
			default: 100
		}
	},

	run: function(cache, settings, callback) {
		var config = {
            instance_count_threshold: settings.instance_count_threshold || this.settings.instance_count_threshold.default
		};

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var instance_count = 0;

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

			for (i in describeInstances.data) {
				var accountId = describeInstances.data[i].OwnerId;

				for (j in describeInstances.data[i].Instances) {
					var instance = describeInstances.data[i].Instances[j];

					if (instance.State.Name == "running") {
                        instance_count +=1;
					}
				}
			}

            // Too many results to print individually
            if (instance_count > config.instance_count_threshold) {
                results = [];

                helpers.addResult(results, 2,
                    'Over ' + config.instance_count_threshold + ' EC2 instances running, exceeds limits!', region, null, custom);
            } else {
				helpers.addResult(results, 0,
					'All ' + instance_count + ' instances are within the expected count.', region);
			}

			rcb();
		}, function(){
			callback(null, results, source);
		});
	}
};
