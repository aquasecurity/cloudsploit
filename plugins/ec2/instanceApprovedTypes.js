var async   = require('async');
var helpers = require('../../helpers');


module.exports = {
	title: 'EC2 Approved Instance Types',
	category: 'EC2',
	description: 'Checks for the running instances and validates they are in the approved list',
	more_info: 'It is recommended to monitor running instances, to prevent unauthorized launch of unnaproved types and running excessive costs under your AWS account',
	link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
	recommended_action: 'Go to the ec2 dashboard and audit the instances running, apparently unauthorized instances have been launched.',
	apis: ['EC2:describeInstances'],
	settings: {
        instance_count_region_approved_types_us_east_1: {
            name: 'us-east-1 : Approved Instance Types Region',
            description: 'Checks for instance types running in the specified region and triggers a failing result if non authorized types are found',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_us_east_2: {
            name: 'us-east-2 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_us_west_1: {
            name: 'us-west-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_us_west_2: {
            name: 'us-west-2 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ap_northeast_1: {
            name: 'ap-northeast-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ap_northeast_2: {
            name: 'ap-northeast-2 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ap_southeast_1: {
            name: 'ap-southeast-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ap_southeast_2: {
            name: 'ap-southeast-2 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_eu_central_1: {
            name: 'eu-central-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_eu_west_1: {
            name: 'eu-west-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_eu_west_2: {
            name: 'eu-west-2 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_eu_west_3: {
            name: 'eu-west-3 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_sa_east_1: {
            name: 'sa-east-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ap_south_1: {
            name: 'ap-south-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_approved_types_ca_central_1: {
            name: 'ca-central-1 : Approved Instance Types Region',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        }
	},

	run: function(cache, settings, callback) {
		var config = {
            instance_count_region_approved_types_us_east_1: settings.instance_count_region_approved_types_us_east_1 || this.settings.instance_count_region_approved_types_us_east_1,
            instance_count_region_approved_types_us_east_2: settings.instance_count_region_approved_types_us_east_2 || this.settings.instance_count_region_approved_types_us_east_2,
            instance_count_region_approved_types_us_west_1: settings.instance_count_region_approved_types_us_west_1 || this.settings.instance_count_region_approved_types_us_west_1,
            instance_count_region_approved_types_us_west_2: settings.instance_count_region_approved_types_us_west_2 || this.settings.instance_count_region_approved_types_us_west_2,
            instance_count_region_approved_types_ap_northeast_1: settings.instance_count_region_approved_types_ap_northeast_1 || this.settings.instance_count_region_approved_types_ap_northeast_1,
            instance_count_region_approved_types_ap_northeast_2: settings.instance_count_region_approved_types_ap_northeast_2 || this.settings.instance_count_region_approved_types_ap_northeast_2,
            instance_count_region_approved_types_ap_southeast_1: settings.instance_count_region_approved_types_ap_southeast_1 || this.settings.instance_count_region_approved_types_ap_southeast_1,
            instance_count_region_approved_types_ap_southeast_2: settings.instance_count_region_approved_types_ap_southeast_2 || this.settings.instance_count_region_approved_types_ap_southeast_2,
            instance_count_region_approved_types_eu_central_1: settings.instance_count_region_approved_types_eu_central_1 || this.settings.instance_count_region_approved_types_eu_central_1,
            instance_count_region_approved_types_eu_west_1: settings.instance_count_region_approved_types_eu_west_1 || this.settings.instance_count_region_approved_types_eu_west_1,
            instance_count_region_approved_types_eu_west_2: settings.instance_count_region_approved_types_eu_west_2 || this.settings.instance_count_region_approved_types_eu_west_2,
            instance_count_region_approved_types_eu_west_3: settings.instance_count_region_approved_types_eu_west_3 || this.settings.instance_count_region_approved_types_eu_west_3,
            instance_count_region_approved_types_sa_east_1: settings.instance_count_region_approved_types_sa_east_1 || this.settings.instance_count_region_approved_types_sa_east_1,
            instance_count_region_approved_types_ap_south_1: settings.instance_count_region_approved_types_ap_south_1 || this.settings.instance_count_region_approved_types_ap_south_1,
            instance_count_region_approved_types_ca_central_1: settings.instance_count_region_approved_types_ca_central_1 || this.settings.instance_count_region_approved_types_ca_central_1
        };

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var instance_count = 0;
        var instance_count_global_approved_types = 0;

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
                        instance_count_global_approved_types +=1;
                        instance_count +=1;
					} else {

                    }
				}
			}

			// Print region results
			if (eval('config.instance_count_region_approved_types_'+region.replace(new RegExp('-','g'),'_').toString()+'.default')==undefined){
                helpers.addResult(results, 0,
                    'The region ' + region + ' does not have an instances approved type parameter.', region);
			}
            else if (instance_count > eval('config.instance_count_region_approved_types_'+region.replace(new RegExp('-','g'),'_').toString()+'.default')) {
                results = [];
                helpers.addResult(results, 2,
                    'Over ' + eval('config.instance_count_region_approved_types_'+region.replace(new RegExp('-','g'),'_').toString()+'.default') + ' EC2 instances running, exceeds ' + region + ' limits!', region, null, custom);
            } else {
				helpers.addResult(results, 0,
					'All ' + instance_count + ' instances are all within the approved types list.', region);
			}

			rcb();
		});

        // Print global results
        if (instance_count_global_approved_types > config.instance_count_global_approved_types.default) {
            helpers.addResult(results, 2,
                'Over ' + config.instance_count_global_approved_types.default + ' EC2 instances running in all regions, exceeds limits!', null, null, custom);
        } else {
            helpers.addResult(results, 0,
                'All ' + instance_count_global_approved_types + ' instances are all within the approved types list.', null);
        }

        callback(null, results, source);
	}
};
