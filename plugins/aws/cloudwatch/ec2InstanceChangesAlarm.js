var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 Instance Changes Alarm',
    category: 'CloudWatch',
    domain: 'Compliance',
    description: 'Ensure that there is an Amazon CloudWatch alarm implemented within your AWS Master account that is triggered each time an administrator-specific action occurs within your AWS EC2 Instances.',
    more_info: 'Using Amazon CloudWatch alarms to detect administrator-specific changes such as create organization, delete organization, create new accounts within an organization or remove a member account from an organization is considered best practice and can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches.',
    recommended_action: 'Ensure that alarms are enabled for organizations to alert the user of the changes being made.',
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
                    `Unable to list CloudWatch metric alarms: ${helpers.addError(describeAlarmForEC2InstanceMetric)}`, 
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