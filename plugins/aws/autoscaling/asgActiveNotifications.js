var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Notifications Active',
    category: 'AutoScaling',
    description: 'Ensures auto scaling groups have notifications active.',
    more_info: 'Notifications can be sent to an SNS endpoint when scaling actions occur, which should be set to ensure all scaling activity is recorded.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/ASGettingNotifications.html',
    recommended_action: 'Add a notification endpoint to the auto scaling group.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeNotificationConfigurations'],

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

            async.each(describeAutoScalingGroups.data, function(asg, cb){
                var resource = asg.AutoScalingGroupARN;
                var notificationConfiguration = helpers.addSource(cache, source,
                    ['autoscaling', 'describeNotificationConfigurations', region, asg.AutoScalingGroupARN]);

                if (!notificationConfiguration || notificationConfiguration.err || !notificationConfiguration.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for auto scaling group notification configurations: ' + 
                        helpers.addError(notificationConfiguration), region, resource);
                    return cb();
                }
    
                if (!notificationConfiguration.data.NotificationConfigurations ||
                    !notificationConfiguration.data.NotificationConfigurations.length) {
                    helpers.addResult(results, 2,
                        'Auto scaling group: ' + asg.AutoScalingGroupName + ' does not have notifications active',
                        region, resource);
                    return cb();
                } else {
                    helpers.addResult(results, 0,
                        'Auto scaling group: ' + asg.AutoScalingGroupName + ' has notifications active',
                        region, resource);
                }

                cb();
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
