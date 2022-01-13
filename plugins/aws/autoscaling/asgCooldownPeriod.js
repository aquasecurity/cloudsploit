var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Group Cooldown Period',
    category: 'AutoScaling',
    domain: 'Availability',
    description: 'Ensure that your AWS Auto Scaling Groups are configured to use a cooldown period.',
    more_info: 'A scaling cooldown helps you prevent your Auto Scaling group from launching or terminating additional instances before the effects of previous activities are visible.'+
        'When you use simple scaling, after the Auto Scaling group scales using a simple scaling policy, it waits for a cooldown period to complete before any further scaling activities initiated by simple scaling policies can start.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html',
    recommended_action: 'Implementing a proper cooldown period to temporarily suspend any scaling actions.',
    apis: ['AutoScaling:describeAutoScalingGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for auto scaling groups: ' + 
                    helpers.addError(describeAutoScalingGroups), region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No auto scaling groups found', region);
                return rcb();
            }

            for (let group of describeAutoScalingGroups.data){
                if (!group.AutoScalingGroupARN) continue;

                let resource = group.AutoScalingGroupARN;
                
                if (group.DefaultCooldown) {
                    helpers.addResult(results, 0,
                        'Amazon Auto Scaling Groups are utilizing cooldown periods.',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'The cooldown period setting is not properly configured for the selected Amazon ASG.',
                        region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
