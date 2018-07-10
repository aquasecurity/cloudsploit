var async   = require('async');
var helpers = require('../../helpers');
var config  = require('../../../../config/db.js');
var db 		= require('../../../../models');

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
            name: 'Max Global Instances',
            description: 'Checks for the number of running instances globally and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 200
        },
        instance_count_region_threshold_us_east_1: {
            name: 'us-east-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_us_east_2: {
            name: 'us-east-2 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_us_west_1: {
            name: 'us-west-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_us_west_2: {
            name: 'us-west-2 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ap_northeast_1: {
            name: 'ap-northeast-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ap_northeast_2: {
            name: 'ap-northeast-2 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ap_southeast_1: {
            name: 'ap-southeast-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ap_southeast_2: {
            name: 'ap-southeast-2 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_eu_central_1: {
            name: 'eu-central-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_1: {
            name: 'eu-west-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_2: {
            name: 'eu-west-2 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_3: {
            name: 'eu-west-3 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_sa_east_1: {
            name: 'sa-east-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ap_south_1: {
            name: 'ap-south-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        },
        instance_count_region_threshold_ca_central_1: {
            name: 'ca-central-1 : Max Instances',
            description: 'Checks for the number of running instances in each region and triggers a failing result if it exceeds the specified count',
            regex: '^[1-2]{1}[0-9]{0,2}$',
            default: 100
        }
	},

	run: function(cache, settings, callback) {
		var config = {
            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold,
            instance_count_region_threshold_us_east_1: settings.instance_count_region_threshold_us_east_1 || this.settings.instance_count_region_threshold_us_east_1,
            instance_count_region_threshold_us_east_2: settings.instance_count_region_threshold_us_east_2 || this.settings.instance_count_region_threshold_us_east_2,
            instance_count_region_threshold_us_west_1: settings.instance_count_region_threshold_us_west_1 || this.settings.instance_count_region_threshold_us_west_1,
            instance_count_region_threshold_us_west_2: settings.instance_count_region_threshold_us_west_2 || this.settings.instance_count_region_threshold_us_west_2,
            instance_count_region_threshold_ap_northeast_1: settings.instance_count_region_threshold_ap_northeast_1 || this.settings.instance_count_region_threshold_ap_northeast_1,
            instance_count_region_threshold_ap_northeast_2: settings.instance_count_region_threshold_ap_northeast_2 || this.settings.instance_count_region_threshold_ap_northeast_2,
            instance_count_region_threshold_ap_southeast_1: settings.instance_count_region_threshold_ap_southeast_1 || this.settings.instance_count_region_threshold_ap_southeast_1,
            instance_count_region_threshold_ap_southeast_2: settings.instance_count_region_threshold_ap_southeast_2 || this.settings.instance_count_region_threshold_ap_southeast_2,
            instance_count_region_threshold_eu_central_1: settings.instance_count_region_threshold_eu_central_1 || this.settings.instance_count_region_threshold_eu_central_1,
            instance_count_region_threshold_eu_west_1: settings.instance_count_region_threshold_eu_west_1 || this.settings.instance_count_region_threshold_eu_west_1,
            instance_count_region_threshold_eu_west_2: settings.instance_count_region_threshold_eu_west_2 || this.settings.instance_count_region_threshold_eu_west_2,
            instance_count_region_threshold_eu_west_3: settings.instance_count_region_threshold_eu_west_3 || this.settings.instance_count_region_threshold_eu_west_3,
            instance_count_region_threshold_sa_east_1: settings.instance_count_region_threshold_sa_east_1 || this.settings.instance_count_region_threshold_sa_east_1,
            instance_count_region_threshold_ap_south_1: settings.instance_count_region_threshold_ap_south_1 || this.settings.instance_count_region_threshold_ap_south_1,
            instance_count_region_threshold_ca_central_1: settings.instance_count_region_threshold_ca_central_1 || this.settings.instance_count_region_threshold_ca_central_1
        };

		var custom = helpers.isCustom(settings, this.settings);

		var results = [];
		var source = {};
		var instance_count = 0;
        var instance_count_global_threshold = 0;
        var my_test_id = 0;

        db.test.findOne({
            attributes: ['id'],
            where: {
                title: 'EC2 Max Instances'
            }
        }).then(function(test){
            if (!test) {
                console.log('Not found')
            } else {
                my_test_id = test.id;
                db.customization.destroy({
                    where: {
                        test_id: test.id
                    }
                }).then(function(deletedCustomizations){
                    console.log('Has the Customization been deleted? 1 means yes, 0 means no: ' + deletedCustomizations.toString());
                });
            }

            helpers.regions.ec2.forEach(function(region){

                var customizationConfig = eval('config.instance_count_region_threshold_'+region.replace(new RegExp('-','g'),'_').toString());

                var customizationBuild = db.customization.build({
                    setting: 'instance_count_region_threshold_'+region.replace(new RegExp('-','g'),'_').toString(),
                    default: customizationConfig.default,
                    name: customizationConfig.name,
                    description: customizationConfig.description,
                    regex: customizationConfig.regex,
                    created: new Date(new Date() -  60 * 1000 * config.REALTIME_DESCRIBE_EXPIRATION),
                    test_id: my_test_id
                });

                customizationBuild.save().then(function(savedCustomization){
                        console.log(('Created: ' + savedCustomization.id.toString()));
                    });
            });

            var customizationConfig = eval('config.instance_count_global_threshold');

            var customizationBuild = db.customization.build({
                setting: 'instance_count_global_threshold',
                default: customizationConfig.default,
                name: customizationConfig.name,
                description: customizationConfig.description,
                regex: customizationConfig.regex,
                created: new Date(new Date() -  60 * 1000 * config.REALTIME_DESCRIBE_EXPIRATION),
                test_id: my_test_id
            });

            customizationBuild.save().then(function(savedCustomization){
                console.log(('Created: ' + savedCustomization.id.toString()));
            });

        }, null);
	}
};
