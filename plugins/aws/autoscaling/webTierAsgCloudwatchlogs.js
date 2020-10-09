var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web-Tier Auto Scaling Group CloudWatch Logs Enabled',
    category: 'autoscaling',
    description: 'Ensures that an agent for AWS CloudWatch Logs is installed within Web-Tier Auto Scaling Group.',
    more_info: '',
    link: '',
    recommended_action: '',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations', 'STS:getCallerIdentity'],
    settings: {
        web_tier_tag_key: {
            name: 'Auto Scaling Web-Tier Tag Key',
            description: 'Web-Tier tag key used by Auto Scaling groups to indicate Web-Tier groups',
            regex: '[a-zA-Z0-9-,]',
            default: 'web_tier'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var webTierTagKey = settings.web_tier_tag_key || this.settings.web_tier_tag_key.default;

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

            var webTierAsgFound = false;
            async.each(describeAutoScalingGroups.data, function(asg, cb){

                var webTierTag = false;
                if(asg.Tags && asg.Tags.length){
                   asg.Tags.forEach(function(tag) {
                        if(tag && tag.Key && tag.Key === webTierTagKey) {
                            webTierTag = true;
                            webTierAsgFound = true;
                        }
                    });
                }

                if (webTierTag) {
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

                if (!webTierAsgFound) {
                    helpers.addResult(results, 0,
                        'No Web-Tier auto scaling groups found', region);
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