var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling Notifications Active',
    category: 'AutoScaling',
    description: 'Ensures autoscaling groups have notifications active.',
    more_info: 'Notifications can be sent to an SNS endpoint when scaling actions occur, which should be set to ensure all scaling activity is recorded.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/ASGettingNotifications.html',
    recommended_action: 'Add a notification endpoint to the autoscaling group.',
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
                var notificationConfiguration = helpers.addSource(cache, source,
                    ['autoscaling', 'describeNotificationConfigurations', region, asg.AutoScalingGroupName]);

                if (!notificationConfiguration) return cb();

                if (notificationConfiguration.err || !notificationConfiguration.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for auto scaling group notification configurations: ' + 
                        helpers.addError(notificationConfiguration), region, asg.AutoScalingGroupName);
                    return cb();
                }
    
                if (!notificationConfiguration.data.length) {
                    helpers.addResult(results, 2, 'No auto scaling group notification configurations found', region);
                    return cb();
                }
                var configurationsList = [];
                notificationConfiguration.data.forEach(function(config){
                    if(config.NotificationType && config.TopicARN) {
                        var notificationType = config.NotificationType;
                        var topicARN = config.TopicARN;
                        configurationsList.push({notificationType, topicARN});
                    }
                });
                if (configurationsList.length) {
                    helpers.addResult(results, 0,
                        'Auto scaling group has the following notification configurations ', region, configurationsList);
                }
                else {
                    helpers.addResult(results, 2,
                        'Auto scaling group does not have any notification configurations ', region, asg.AutoScalingGroupName);
                }

                cb();
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
