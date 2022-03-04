var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Organization Changes Alarm',
    category: 'CloudWatch',
    domain: 'Compliance',
    description: 'Ensure that there is an Amazon CloudWatch alarm implemented within your AWS account to detect administrator-specific actions occurred within your AWS Organization.',
    more_info: 'Using Amazon CloudWatch alarms to detect administrator-specific changes such as create organization, delete organization, create new accounts within an organization or remove a member account from an organization is considered best practice and can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches.',
    recommended_action: 'Create a CloudWatch alarm to detect any administrator changes within you AWS organization.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    apis: ['CloudWatch:describeAlarmForOrgEventsMetric'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudwatch, function(region, rcb){
            var describeAlarmForOrgEventsMetric = helpers.addSource(cache, source,
                ['cloudwatch', 'describeAlarmForOrgEventsMetric', region]);

            if (!describeAlarmForOrgEventsMetric) return rcb();

            if (describeAlarmForOrgEventsMetric.err || !describeAlarmForOrgEventsMetric.data) {
                helpers.addResult(results, 3,
                    `Unable to describe CloudWatch metric alarms: ${helpers.addError(describeAlarmForOrgEventsMetric)}`, 
                    region);
                return rcb();
            }

            if (describeAlarmForOrgEventsMetric.data.length) {
                helpers.addResult(results, 0,
                    'CloudWatch Alarm exists to detect organization changes', 
                    region);
            } else {
                helpers.addResult(results, 2,
                    'CloudWatch Alarm does not exist to detect organization changes',
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};