var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier Launch Configurations IAM Roles',
    category: 'AutoScaling',
    description: 'Ensures that App-Tier Auto Scaling launch configuration is configured to use a customer created IAM role.',
    more_info: 'App-Tier Auto Scaling launch configuration should have a customer created App-Tier IAM role to provide necessary credentials to access AWS services.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html',
    recommended_action: 'Update App-Tier Auto Scaling launch configuration and attach a customer created App-Tier IAM role',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by Auto Scaling groups to indicate App-Tier groups',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var app_tier_tag_key = settings.app_tier_tag_key || this.settings.app_tier_tag_key.default;

        if (!app_tier_tag_key.length) return callback();

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            var describeLaunchConfigurations = helpers.addSource(cache, source,
                ['autoscaling', 'describeLaunchConfigurations', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Auto Scaling groups: ${helpers.addError(describeAutoScalingGroups)}`,
                    region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
                return rcb();
            }

            if (!describeLaunchConfigurations || describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Auto Scaling group launch configurations: ${helpers.addError(describeLaunchConfigurations)}`,
                    region);
                return rcb();
            }

            if (!describeLaunchConfigurations.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling launch configurations found', region);
                return rcb();
            }

            var launchConfigurations = {};
            describeLaunchConfigurations.data.forEach(config => {
                if (!config.IamInstanceProfile) return;

                launchConfigurations[config.LaunchConfigurationName] = config.IamInstanceProfile;
            });

            var launchConfigurationAsgFound = false;
            var appTierAsgFound = false;

            for (var g in describeAutoScalingGroups.data) {
                var asg = describeAutoScalingGroups.data[g];

                if (!asg.AutoScalingGroupARN) continue;

                var resource = asg.AutoScalingGroupARN;

                if(asg.LaunchConfigurationName && asg.LaunchConfigurationName.length){
                    launchConfigurationAsgFound = true;

                    if (asg.Tags && asg.Tags.length) {
                        var appTierTag = false;

                        for (var t in asg.Tags) {
                            var tag = asg.Tags[t];

                            if (tag.Key === app_tier_tag_key) {
                                appTierTag = true;
                                appTierAsgFound = true;
                                break;
                            }
                        }

                        if (appTierTag) {
                            if(launchConfigurations[asg.LaunchConfigurationName]) {
                                helpers.addResult(results, 0,
                                    `Launch configuration for App-Tier group "${asg.AutoScalingGroupName}" has customer created IAM role configured`,
                                    region, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    `Launch configuration for App-Tier group "${asg.AutoScalingGroupName}" does not have customer created IAM role configured`,
                                    region, resource);
                            }
                        }
                    }
                }
            }

            if (!launchConfigurationAsgFound) {
                helpers.addResult(results, 0,
                    'No Auto Scaling groups utilizing launch configurations found', region);
                return rcb();
            }

            if (!appTierAsgFound) {
                helpers.addResult(results, 0,
                    'No App-Tier Auto Scaling groups with found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
