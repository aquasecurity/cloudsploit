var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Flow Logs Metric Alarm',
    category: 'CloudWatch',
    domain: 'Compliance',
    severity: 'LOW',
    description: 'Ensure that an AWS CloudWatch alarm exists and configured for metric filter attached with VPC flow logs CloudWatch group.',
    more_info: 'A metric alarm watches a single CloudWatch metric or the result of a math expression based on CloudWatch metrics. ' + 
        'The alarm performs one or more actions based on the value of the metric or expression relative to a threshold over a number of time periods. ' +
        'The action can be sending a notification to an Amazon SNS topic.',
    recommended_action: 'Create a CloudWatch group, attached metric filter to log VPC flow logs changes and create an CloudWatch alarm for the metric filter.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    apis: ['CloudWatchLogs:describeMetricFilters', 'CloudWatch:describeAlarms'],
    settings: {
        vpc_flow_log_group: {
            name: 'CloudWatch VPC Flow Log Group Name',
            description: 'Existing CloudWatch log group name created to log VPC flow logs',
            regex: '^.*$',
            default: 'vpc_flow_logs'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            vpc_flow_log_group: settings.vpc_flow_log_group || this.settings.vpc_flow_log_group.default
        };

        if (!config.vpc_flow_log_group.length) return callback(null, results, source);

        async.each(regions.cloudwatchlogs, function(region, rcb){
            var describeMetricFilters = helpers.addSource(cache, source,
                ['cloudwatchlogs', 'describeMetricFilters', region]);

            if (!describeMetricFilters) return rcb();
            
            if (describeMetricFilters.err || !describeMetricFilters.data) {
                helpers.addResult(results, 3,
                    `Unable to describe CloudWatch logs metric filters: ${helpers.addError(describeMetricFilters)}`, region);
                return rcb();
            }

            if (!describeMetricFilters.data.length) {
                helpers.addResult(results, 2,
                    'No CloudWatch logs metric filters found', region);
                return rcb();
            }

            let cwVpcLogGroup = describeMetricFilters.data.find(metrics => metrics.logGroupName === config.vpc_flow_log_group);

            if (!cwVpcLogGroup) {
                helpers.addResult(results, 2,
                    'Unable to locate the specified log group', region);
                return rcb();
            }

            let metricTransformations = cwVpcLogGroup.metricTransformations && cwVpcLogGroup.metricTransformations.length?
                cwVpcLogGroup.metricTransformations.map(transformation => transformation.metricName) : [];

            var describeAlarms = helpers.addSource(cache, source,
                ['cloudwatch', 'describeAlarms', region]);

            if (!describeAlarms ||
                describeAlarms.err || !describeAlarms.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CloudWatch metric alarms: ' + helpers.addError(describeAlarms), region);
                return rcb();
            }

            if (!describeAlarms.data.length) {
                helpers.addResult(results, 2,
                    'No CloudWatch metric alarms found', region);
                return rcb();
            }

            let metricAlarm =  describeAlarms.data.find(alarm => metricTransformations.includes(alarm.MetricName));

            if (metricAlarm && metricAlarm.AlarmActions && metricAlarm.AlarmActions.length){
                helpers.addResult(results, 0,
                    'CloudWatch alarm is configured for VPC flow logs and has an SNS topic attached for notifications', 
                    region);
            } else if (metricAlarm) {
                helpers.addResult(results, 0,
                    'CloudWatch alarm is configured for the VPC flow logs but has no SNS topic attached for notifications', 
                    region);
            } else {
                helpers.addResult(results, 2,
                    'CloudWatch alarm is not configured for the VPC flow logs', 
                    region);
            }
                    
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
