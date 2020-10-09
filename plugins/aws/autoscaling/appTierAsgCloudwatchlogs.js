var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier Auto Scaling Group CloudWatch Logs Enabled',
    category: 'autoscaling',
    description: 'Ensures that an agent for AWS CloudWatch Logs is installed within App-Tier Auto Scaling Group.',
    more_info: '',
    link: '',
    recommended_action: '',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations', 'STS:getCallerIdentity'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by Auto Scaling groups to indicate App-Tier groups',
            regex: '[a-zA-Z0-9-,]',
            default: 'app_tier'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var appTierTagKey = settings.app_tier_tag_key || this.settings.app_tier_tag_key.default;

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for auto scaling groups: ${helpers.addError(describeAutoScalingGroups)}`,
                    region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No auto scaling groups found', region);
                return rcb();
            }

            var appTierAsgFound = false;
            async.each(describeAutoScalingGroups.data, function(asg, cb){

                var appTierTag = false;
                if(asg.Tags && asg.Tags.length){
                   asg.Tags.forEach(function(tag) {
                        if(tag && tag.Key && tag.Key === appTierTagKey) {
                            appTierTag = true;
                            appTierAsgFound = true;
                        }
                    });
                }

                if (appTierTag) {
                    var resource = asg.AutoScalingGroupARN;

                    var describeLaunchConfigurations = helpers.addSource(cache, source,
                        ['autoscaling', 'describeLaunchConfigurations', region, asg.AutoScalingGroupName]);

                    if(!describeLaunchConfigurations ||
                        describeLaunchConfigurations.err ||
                        !describeLaunchConfigurations.data ||
                        !describeLaunchConfigurations.data.LaunchConfigurations ||
                        !describeLaunchConfigurations.data.LaunchConfigurations.length) {
                        helpers.addResult(results, 3,
                            `Unable to query launch configurations for auto scaling group "${asg.AutoScalingGroupName}": ${helpers.addError(describeLaunchConfigurations)}`,
                            region, resource);
                        return cb();
                    }

                    var logsEnabled = false;                    
                    describeLaunchConfigurations.data.LaunchConfigurations.forEach(function(config){
                        if(config.UserData) {
                            logsEnabled = true;
                        }
                    });

                    if(logsEnabled) {
                        helpers.addResult(results, 0,
                            `Auto scaling group "${asg.AutoScalingGroupName}" has CloudWatch logs enabled`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Auto scaling group "${asg.AutoScalingGroupName}" does not have CloudWatch logs enabled`,
                            region, resource);
                    }
                }

                if (!appTierAsgFound) {
                    helpers.addResult(results, 0,
                        'No App-Tier auto scaling groups found', region);
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