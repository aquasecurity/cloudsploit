var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Roles for Web-Tier ASG Launch Configurations',
    category: 'AutoScaling',
    description: 'Ensures that Web-Tier ASG launch configuration is configured to use a customer created Web-Tier IAM role',
    more_info: 'Web-Tier ASG launch configuration should have a customer created Web-Tier IAM role to provide necessary credentials to access AWS services',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html',
    recommended_action: 'Update Web-Tier ASG launch configuration and attach a customer created Web-Tier IAM role',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations'],
    settings: {
        web_tier_tag_key: {
            name: 'Auto Scaling Web-Tier Tag Key',
            description: 'Web-Tier tag key used by Auto Scaling groups to indicate Web-Tier groups',
            regex: '[a-zA-Z0-9,]',
            default: 'web_tier'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var web_tier_tag_key = settings.web_tier_tag_key || this.settings.web_tier_tag_key.default;

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
                    `Unable to query for Auto Scaling launch configurations: ${helpers.addError(describeLaunchConfigurations)}`,
                    region);
                return rcb();
            }

            if (!describeLaunchConfigurations.data.length) {
                helpers.addResult(results, 2, 'No Auto Scaling launch configurations found', region);
                return rcb();
            }

            var launchConfigurations = {};
            describeLaunchConfigurations.data.forEach(function(config){
                launchConfigurations[config.LaunchConfigurationName] = config.IamInstanceProfile;
            });

            var launchConfigurationAsgFound = false;
            async.each(describeAutoScalingGroups.data, function(asg, cb){
                var resource = asg.AutoScalingGroupARN;
                if(asg.LaunchConfigurationName && asg.LaunchConfigurationName.length){
                    launchConfigurationAsgFound = true;
                    var launchConfigurationName = asg.LaunchConfigurationName;

                    if (!asg.Tags || !asg.Tags.length) {
                        helpers.addResult(results, 0,
                            `Auto Scaling group "${asg.AutoScalingGroupName}" does not contain any tags`,
                            region, resource);
                    }
                    else {
                        var webTierTagFound = false;
                        asg.Tags.forEach(function(tag){
                            if (tag.Key === web_tier_tag_key) {
                                webTierTagFound = true;
                            }
                        });

                        if(webTierTagFound){
                            if(launchConfigurations[launchConfigurationName]) {
                                helpers.addResult(results, 0,
                                    `Auto Scaling launch configuration "${launchConfigurationName}" has "${launchConfigurations[launchConfigurationName]}" customer created Web-Tier IAM role configured`,
                                    region, resource);
                            }
                            else {
                                helpers.addResult(results, 2,
                                    `Auto Scaling launch configuration "${launchConfigurationName}" does have use customer created Web-Tier IAM role configured`,
                                    region, resource);
                            }
                        }
                        else {
                            helpers.addResult(results, 0,
                                `Auto Scaling group "${asg.AutoScalingGroupName}" does not contain Web-Tier tag`,
                                region, resource);
                        }
                    }
                }

                if (!launchConfigurationAsgFound) {
                    helpers.addResult(results, 0,
                        'No Auto Scaling group with launch configurations found',
                        region);
                }

                cb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
