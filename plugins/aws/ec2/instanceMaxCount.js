var async   = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Max Instances',
    category: 'EC2',
    description: 'Ensures the total number of EC2 instances does not exceed a set threshold.',
    more_info: 'The number of running EC2 instances should be carefully audited, especially in unused regions, to ensure only approved applications are consuming compute resources. Many compromised AWS accounts see large numbers of EC2 instances launched.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
    recommended_action: 'Ensure that the number of running EC2 instances matches the expected count. If instances are launched above the threshold, investigate to ensure they are legitimate.',
    apis: ['EC2:describeInstances'],
    settings: {
        instance_count_global_threshold: {
            name: 'Instance Count Global Threshold',
            description: 'Checks for the number of running instances across all regions and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 200
        },
        instance_count_region_threshold_us_east_1: {
            name: 'Instance Count Region Threshold: us-east-1',
            description: 'Checks for the number of running instances in the us-east-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_east_2: {
            name: 'Instance Count Region Threshold: us-east-2',
            description: 'Checks for the number of running instances in the us-east-2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_west_1: {
            name: 'Instance Count Region Threshold: us-west-1',
            description: 'Checks for the number of running instances in the us-west-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_west_2: {
            name: 'Instance Count Region Threshold: us-west-2',
            description: 'Checks for the number of running instances in the us-west-2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_northeast_1: {
            name: 'Instance Count Region Threshold: ap-northeast-1',
            description: 'Checks for the number of running instances in the ap-northeast-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_northeast_2: {
            name: 'Instance Count Region Threshold: ap-northeast-2',
            description: 'Checks for the number of running instances in the ap-northeast-2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_southeast_1: {
            name: 'Instance Count Region Threshold: ap-southeast-1',
            description: 'Checks for the number of running instances in the ap-southeast-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_southeast_2: {
            name: 'Instance Count Region Threshold: ap-southeast-2',
            description: 'Checks for the number of running instances in the ap-southeast-2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_eu_central_1: {
            name: 'Instance Count Region Threshold: eu-central-1',
            description: 'Checks for the number of running instances in the eu-central-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_1: {
            name: 'Instance Count Region Threshold: eu-west-1',
            description: 'Checks for the number of running instances in the eu-west-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_2: {
            name: 'Instance Count Region Threshold: eu-west-2',
            description: 'Checks for the number of running instances in the eu-west-2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_eu_west_3: {
            name: 'Instance Count Region Threshold: eu-west-3',
            description: 'Checks for the number of running instances in the eu-west-3 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_eu_north_1: {
            name: 'Instance Count Region Threshold: eu-north-1',
            description: 'Checks for the number of running instances in the eu-north-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_sa_east_1: {
            name: 'Instance Count Region Threshold: sa-east-1',
            description: 'Checks for the number of running instances in the sa-east-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_south_1: {
            name: 'Instance Count Region Threshold: ap-south-1',
            description: 'Checks for the number of running instances in the ap-south-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ap_east_1: {
            name: 'Instance Count Region Threshold: ap-east-1',
            description: 'Checks for the number of running instances in the ap-east-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_ca_central_1: {
            name: 'Instance Count Region Threshold: ca-central-1',
            description: 'Checks for the number of running instances in the ca-central-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_gov_west_1: {
            name: 'Instance Count Region Threshold: us-gov-west-1',
            description: 'Checks for the number of running instances in the us-gov-west-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_gov_east_1: {
            name: 'Instance Count Region Threshold: us-gov-east-1',
            description: 'Checks for the number of running instances in the us-gov-east-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_cn_north_1: {
            name: 'Instance Count Region Threshold: cn-north-1',
            description: 'Checks for the number of running instances in the cn-north-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_cn_northwest_1: {
            name: 'Instance Count Region Threshold: cn-northwest-1',
            description: 'Checks for the number of running instances in the cn-northwest-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold.default,
            instance_count_region_threshold_us_east_1: settings.instance_count_region_threshold_us_east_1 || this.settings.instance_count_region_threshold_us_east_1.default,
            instance_count_region_threshold_us_east_2: settings.instance_count_region_threshold_us_east_2 || this.settings.instance_count_region_threshold_us_east_2.default,
            instance_count_region_threshold_us_west_1: settings.instance_count_region_threshold_us_west_1 || this.settings.instance_count_region_threshold_us_west_1.default,
            instance_count_region_threshold_us_west_2: settings.instance_count_region_threshold_us_west_2 || this.settings.instance_count_region_threshold_us_west_2.default,
            instance_count_region_threshold_ap_northeast_1: settings.instance_count_region_threshold_ap_northeast_1 || this.settings.instance_count_region_threshold_ap_northeast_1.default,
            instance_count_region_threshold_ap_northeast_2: settings.instance_count_region_threshold_ap_northeast_2 || this.settings.instance_count_region_threshold_ap_northeast_2.default,
            instance_count_region_threshold_ap_southeast_1: settings.instance_count_region_threshold_ap_southeast_1 || this.settings.instance_count_region_threshold_ap_southeast_1.default,
            instance_count_region_threshold_ap_southeast_2: settings.instance_count_region_threshold_ap_southeast_2 || this.settings.instance_count_region_threshold_ap_southeast_2.default,
            instance_count_region_threshold_eu_central_1: settings.instance_count_region_threshold_eu_central_1 || this.settings.instance_count_region_threshold_eu_central_1.default,
            instance_count_region_threshold_eu_west_1: settings.instance_count_region_threshold_eu_west_1 || this.settings.instance_count_region_threshold_eu_west_1.default,
            instance_count_region_threshold_eu_west_2: settings.instance_count_region_threshold_eu_west_2 || this.settings.instance_count_region_threshold_eu_west_2.default,
            instance_count_region_threshold_eu_west_3: settings.instance_count_region_threshold_eu_west_3 || this.settings.instance_count_region_threshold_eu_west_3.default,
            instance_count_region_threshold_eu_north_1: settings.instance_count_region_threshold_eu_north_1 || this.settings.instance_count_region_threshold_eu_north_1.default,
            instance_count_region_threshold_sa_east_1: settings.instance_count_region_threshold_sa_east_1 || this.settings.instance_count_region_threshold_sa_east_1.default,
            instance_count_region_threshold_ap_south_1: settings.instance_count_region_threshold_ap_south_1 || this.settings.instance_count_region_threshold_ap_south_1.default,
            instance_count_region_threshold_ap_east_1: settings.instance_count_region_threshold_ap_east_1 || this.settings.instance_count_region_threshold_ap_east_1.default,
            instance_count_region_threshold_ca_central_1: settings.instance_count_region_threshold_ca_central_1 || this.settings.instance_count_region_threshold_ca_central_1.default,
            instance_count_region_threshold_us_gov_west_1: settings.instance_count_region_threshold_us_gov_west_1 || this.settings.instance_count_region_threshold_us_gov_west_1.default,
            instance_count_region_threshold_us_gov_east_1: settings.instance_count_region_threshold_us_gov_east_1 || this.settings.instance_count_region_threshold_us_gov_east_1.default,
            instance_count_region_threshold_cn_north_1: settings.instance_count_region_threshold_cn_north_1 || this.settings.instance_count_region_threshold_cn_north_1.default,
            instance_count_region_threshold_cn_northwest_1: settings.instance_count_region_threshold_cn_northwest_1 || this.settings.instance_count_region_threshold_cn_northwest_1.default
        };

        for (var c in config) {
            if (Object.prototype.hasOwnProperty.call(settings, c)) {
                config[c] = settings[c];    
            }
        }

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var instanceCountGlobal = 0;

        async.each(regions.ec2, function(region, rcb){

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

            var instanceCount = 0;

            for (var i in describeInstances.data) {
                for (var j in describeInstances.data[i].Instances) {
                    var instance = describeInstances.data[i].Instances[j];

                    if (instance.State.Name == 'running') {
                        instanceCountGlobal +=1;
                        instanceCount +=1;
                    }
                }
            }

            // Print region results
            var regionUnderscore = region.replace(/-/g, '_');
            var regionThreshold = config['instance_count_region_threshold_'+regionUnderscore];

            if (!regionThreshold) {
                helpers.addResult(results, 3,
                    'The region: ' + region + ' does not have a maximum instances count setting.', region);
            } else if (instanceCount > regionThreshold) {
                helpers.addResult(results, 2,
                    instanceCount + ' EC2 instances running in ' +
                    region + ' region, exceeding limit of: ' +
                    regionThreshold, region, null, custom);
            } else {
                helpers.addResult(results, 0,
                    instanceCount + ' instances in the region are within the regional expected count of: ' + regionThreshold, region, null, custom);
            }

            rcb();
        });

        // Print global results
        var globalThreshold = config.instance_count_global_threshold;

        if (instanceCountGlobal > globalThreshold) {
            helpers.addResult(results, 2,
                instanceCountGlobal + ' EC2 instances running in all regions, exceeding limit of: ' + globalThreshold, null, null, custom);
        } else {
            helpers.addResult(results, 0,
                instanceCountGlobal + ' instances in the account are within the global expected count of: ' + globalThreshold, null, null, custom);
        }

        callback(null, results, source);
    }
};
