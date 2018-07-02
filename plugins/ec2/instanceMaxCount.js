var async = require('async');
var helpers = require('../../helpers');

module.exports = {
	title: 'EC2 Max Instances',
	category: 'EC2',
	description: 'Checks for the number of running instances in an account and triggers a failing result if it exceeds a certain count',
	more_info: 'It is recommended not to use the default key to keep track of the number of running instances, to prevent unauthorized launch and running excessive costs under your AWS account',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
	recommended_action: 'Go to the ec2 dashboard and audit the instances running, apparently additional unauthorized instances have been launched.',
	apis: ['EC2:describeInstances'],
	settings: {
        instance_count_global_threshold: {
            name: 'Instance Count Global Threshold',
            description: 'Checks for the number of running instances globally and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 200
        },
		instance_count_region_threshold: {
			name: 'Instance Count Region Threshold',
			description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
			regex: '^[1-2]{1}[0-9]{0,2}$',
			default: 100
		}
	},

	run: function(cache, settings, callback) {
		var config = {
            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold.default,
            instance_count_region_threshold: settings.instance_count_region_threshold || this.settings.instance_count_region_threshold.default
        };

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var instance_count = 0;
        var instance_count_global_threshold = 0;

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
                        instance_count_global_threshold +=1;
                        instance_count +=1;
					}
				}
			}

			// Print region results
            if (instance_count > config.instance_count_region_threshold) {
                results = [];
                helpers.addResult(results, 2,
                    'Over ' + config.instance_count_region_threshold + ' EC2 instances running, exceeds ' + region + ' limits!', region, null, custom);
            } else {
				helpers.addResult(results, 0,
					'All ' + instance_count + ' instances are within the expected count.', region);
			}

			rcb();
		});

        // Print global results
        if (instance_count_global_threshold > config.instance_count_global_threshold) {
            helpers.addResult(results, 2,
                'Over ' + config.instance_count_global_threshold + ' EC2 instances running in all regions, exceeds limits!', null, null, custom);
        } else {
            helpers.addResult(results, 0,
                'All ' + instance_count_global_threshold + ' instances in the account are within the global expected count.', null);
        }

        callback(null, results, source);
	}
};
