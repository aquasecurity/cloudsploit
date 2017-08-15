var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'ASG Multiple AZ',
    category: 'AutoScaling',
    description: 'Ensures that ASGs are created to be cross-AZ for high availability.',
    more_info: 'ASGs can easily be configured to allow instances to launch in multiple availability zones. This ensures that the ASG can continue to scale, even when AWS is experiencing downtime in one or more zones.',
    link: 'http://docs.aws.amazon.com/autoscaling/latest/userguide/AutoScalingGroup.html',
    recommended_action: 'Modify the autoscaling instance to enable scaling across multiple availability zones.',
    apis: ['AutoScaling:describeAutoScalingGroups'],

    run: function(cache, callback) {
        var results = [];
        var source = {};
        async.each(helpers.regions.autoscaling, function(region, rcb){
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

            // loop through autoscaling Instances
            describeAutoScalingGroups.data.forEach(function(Asg){
                if (Asg.AvailabilityZones.length <=1) {
                    helpers.addResult(results, 2,
                        'Auto scaling group is only using ' + Asg.AvailabilityZones.length +
                        ' availability zones',
                        region, Asg.AutoScalingGroupName);
                } else {
                    helpers.addResult(results, 0,
                        'Auto scaling group using ' + Asg.AvailabilityZones.length +
                        ' availability zones',
                        region, Asg.AutoScalingGroupName);
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
