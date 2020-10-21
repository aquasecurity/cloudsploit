var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web-Tier Auto Scaling Group Associated ELB',
    category: 'AutoScaling',
    description: 'Ensures that Web-Tier Auto Scaling Group has an associated Elastic Load Balancer',
    more_info: 'Web-Tier Auto Scaling groups should have an ELB associated to distribute incoming traffic across EC2 instances.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Update Web-Tier Auto Scaling group to associate ELB to distribute incoming traffic.',
    apis: ['AutoScaling:describeAutoScalingGroups'],
    settings: {
        web_tier_tag_key: {
            name: 'Auto Scaling Web-Tier Tag Key',
            description: 'Web-Tier tag key used by Auto Scaling groups to indicate Web-Tier groups',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var web_tier_tag_key = settings.web_tier_tag_key || this.settings.web_tier_tag_key.default;

        if (!web_tier_tag_key.length) return callback();

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

            var webTierAsgFound = false;
            describeAutoScalingGroups.data.forEach(asg => {
                if (!asg.AutoScalingGroupARN) return;

                var resource = asg.AutoScalingGroupARN;

                if (asg.Tags && asg.Tags.length) {
                    var webTierTagFound = false;

                    for (var t in asg.Tags) {
                        var tag = asg.Tags[t];

                        if (tag.Key === web_tier_tag_key) {
                            webTierTagFound = true;
                            break;
                        }
                    }

                    if(webTierTagFound) {
                        webTierAsgFound = true;

                        if(asg.LoadBalancerNames && asg.LoadBalancerNames.length) {
                            helpers.addResult(results, 0,
                                `Auto Scaling group "${asg.AutoScalingGroupName}" has load balancers associated`,
                                region, resource);
                        }
                        else {
                            helpers.addResult(results, 2,
                                `Auto Scaling group "${asg.AutoScalingGroupName}" does have any load balancers associated`,
                                region, resource);
                        }
                    }
                }
            });

            if (!webTierAsgFound) {
                helpers.addResult(results, 0,
                    'No Web-Tier Auto Scaling groups found',
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
