var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Group Cooldown Period',
    category: 'AutoScaling',
    domain: 'Availability',
    description: 'Ensure that your AWS Auto Scaling Groups are configured to use a cool down period.',
    more_info: 'A scaling cool down helps you prevent your Auto Scaling group from launching or terminating additional instances before the effects of previous activities are visible.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html',
    recommended_action: 'Implement proper cool down period for Auto Scaling groups to temporarily suspend any scaling actions.',
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
                    'Unable to query for Auto Scaling groups: ' + 
                    helpers.addError(describeAutoScalingGroups), region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
                return rcb();
            }

            for (let group of describeAutoScalingGroups.data){
                if (!group.AutoScalingGroupARN) continue;

                let resource = group.AutoScalingGroupARN;
                
                if (group.DefaultCooldown) {
                    helpers.addResult(results, 0,
                        'Auto Scaling group has cool down period configured',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Auto Scaling group does not have cool down period configured',
                        region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
