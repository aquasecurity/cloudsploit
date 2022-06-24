var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier ASG Launch Configurations Approved AMIs',
    category: 'AutoScaling',
    domain: 'Availability',
    description: 'Ensures that App-Tier Auto Scaling Group Launch Configurations are using approved AMIs.',
    more_info: 'App-Tier Auto Scaling Group Launch Configurations should use approved AMIs only to launch EC2 instances within the ASG',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html',
    recommended_action: 'Update App-Tier ASG Launch Configurations to use approved AMIs only',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by Auto Scaling groups to indicate App-Tier groups',
            regex: '^.*$',
            default: ''
        },
        approved_amis: {
            name: 'Approved AMIs for ASG Launch Configuration',
            description: 'List of approved AMIs for ASG Launch Configuration',
            regex: '[a-zA-Z0-9-,]',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            app_tier_tag_key: settings.app_tier_tag_key || this.settings.app_tier_tag_key.default,
            approved_amis: settings.approved_amis || this.settings.approved_amis.default
        };

        if (!config.app_tier_tag_key.length) return callback(null, results, source);

        config.approved_amis = config.approved_amis.split(',');

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

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

            var appTierAsgFound = false;
            async.each(describeAutoScalingGroups.data, function(asg, cb){
                var appTierTag = false;
                if (asg.Tags && asg.Tags.length){
                    for (var t in asg.Tags) {
                        var tag = asg.Tags[t];
                        if (tag.Key && tag.Key === config.app_tier_tag_key) {
                            appTierTag = true;
                            appTierAsgFound = true;
                            break;
                        }
                    }
                }

                if (appTierTag) {
                    var resource = asg.AutoScalingGroupARN;
                    var describeLaunchConfigurations = helpers.addSource(cache, source,
                        ['autoscaling', 'describeLaunchConfigurations', region, asg.AutoScalingGroupARN]);

                    var imageFound = false;
                    var unapprovedAmis = [];

                    if (!describeLaunchConfigurations ||
                        describeLaunchConfigurations.err ||
                        !describeLaunchConfigurations.data ||
                        !describeLaunchConfigurations.data.LaunchConfigurations ||
                        !describeLaunchConfigurations.data.LaunchConfigurations.length) {
                        helpers.addResult(results, 3,
                            `Unable to query launch configurations for Auto Scaling group "${asg.AutoScalingGroupName}": ${helpers.addError(describeLaunchConfigurations)}`,
                            region, resource);
                        return cb();
                    }

                    describeLaunchConfigurations.data.LaunchConfigurations.forEach(function(launchConfig){
                        if (launchConfig.ImageId) {
                            imageFound = true;
                            if (config.approved_amis.indexOf(launchConfig.ImageId) === -1){
                                unapprovedAmis.push(launchConfig.ImageId);
                            }
                        }
                    });

                    if (imageFound) {
                        if (!unapprovedAmis.length) {
                            helpers.addResult(results, 0,
                                `Launch Configuration for App-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is using approved AMI`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `Launch Configuration for App-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is using this unapproved AMI: ${unapprovedAmis.join(', ')}`,
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            `Launch Configuration for App-Tier Auto Scaling group "${asg.AutoScalingGroupName}" is not using any AMI`,
                            region, resource);
                    }
                }

                if (!appTierAsgFound) {
                    helpers.addResult(results, 0,
                        'No App-Tier Auto Scaling groups found', region);
                }

                cb();
            }, function(){
                rcb();
            });

        }, function(){
            callback(null, results, source);
        });

    }
}; 