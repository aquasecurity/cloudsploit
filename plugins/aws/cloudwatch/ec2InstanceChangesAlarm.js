var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Instance Changes Alarm',
    category: 'CloudWatch',
    domain: 'Compliance',
    description: 'Ensure that  each time an administrator-specific action occurs within your AWS EC2 Instances, there is an Amazon CloudWatch alarm implemented within your AWS Master account that is triggered.',
    more_info: 'Using Amazon CloudWatch alarm actions, you can create alarms that automatically stop, terminate, reboot, or recover your EC2 instances. You can use the stop or terminate actions to help you save money when you no longer need an instance to be running.',
    recommended_action: 'You can create a CloudWatch alarm that monitors CloudWatch metrics for one of your instances. CloudWatch will automatically send you a notification when the metric reaches a threshold you specify.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    apis: ['CloudWatch:describeAlarmForEC2InstanceMetric'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudwatch, function(region, rcb){
            var describeAlarmForEC2InstanceMetric = helpers.addSource(cache, source,
                ['cloudwatch', 'describeAlarmForEC2InstanceMetric', region]);

            if (!describeAlarmForEC2InstanceMetric) return rcb();

            if (describeAlarmForEC2InstanceMetric.err || !describeAlarmForEC2InstanceMetric.data) {
                helpers.addResult(results, 3,
                    `Unable to describe CloudWatch metric alarms: ${helpers.addError(describeAlarmForEC2InstanceMetric)}`, 
                    region);
                return rcb();
            }

            if (describeAlarmForEC2InstanceMetric.data.length) {
                helpers.addResult(results, 0,
                    'Alarms detecting changes in EC2 instances are enabled', 
                    region);
            } else {
                helpers.addResult(results, 2,
                    'Alarms detecting changes in EC2 instances are not enabled',
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};