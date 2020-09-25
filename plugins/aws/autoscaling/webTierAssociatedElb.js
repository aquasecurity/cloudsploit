var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web-Tier Auto Scaling Group Associated ELB',
    category: 'AutoScaling',
    description: 'Ensures that Web-Tier Auto Scaling Group has an associated Elastic Load Balancer',
    more_info: 'Web-Tier ASG group should have ELB associated to distribute incoming traffic across EC2 instances',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Update Web-Tier ASG and associate ELB to the group to distribute incoming traffic',
    apis: ['AutoScaling:describeAutoScalingGroups'],
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

            async.each(describeAutoScalingGroups.data, function(asg, cb){
                var resource = asg.AutoScalingGroupARN;

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

                    if(webTierTagFound) {
                        if(asg.LoadBalancerNames && asg.LoadBalancerNames.length) {
                            helpers.addResult(results, 0,
                                `Auto Scaling group "${asg.AutoScalingGroupName}" has "${asg.LoadBalancerNames.join(' , ')}" load balancers associated`,
                                region, resource);
                        }
                        else {
                            helpers.addResult(results, 2,
                                `Auto Scaling group "${asg.AutoScalingGroupName}" does have any load balancer associated`,
                                region, resource);
                        }
                    }
                    else {
                        helpers.addResult(results, 0,
                            `Auto Scaling group "${asg.AutoScalingGroupName}" does not contain Web-Tier tag`,
                            region, resource);
                    }
                }

                cb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
