var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Flow Logs Metric Alarm',
    category: 'CloudWatch',
    domain: 'Compliance',
    description: 'Ensures metric filters are setup for alarms by CloudWatch to detect any changes from VPC.',
    more_info: 'A metric alarm watches a single CloudWatch metric or the result of a math expression based on CloudWatch metrics. The alarm performs one or more actions based on the value of the metric or expression relative to a threshold over a number of time periods. The action can be sending a notification to an Amazon SNS topic.',
    recommended_action: '1. Create a log group in CloudWatch logs; 2. Create a metric filter for log group with Namespace=LogMetrics and metric Threshold=1; 3.Create CloudWatch alarm for the metric filter',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    apis: ['CloudWatchLogs:describeMetricFilters', 'CloudWatch:describeAlarms'],
    settings: {
        vpc_flow_log_group: {
            name: 'CloudWatch VPC flow log group name',
            description: 'Log group name for VPC to detect the log group being used by CLoudWatch logs',
            regex: '^.*$',
            default: ''
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

            let filters = describeMetricFilters.data.find(metrics => metrics.logGroupName === config.vpc_flow_log_group);
            if (!filters) {
                helpers.addResult(results, 2,
                    'No desired VPC group found', region);
                return rcb();
            }

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

            let alarms =  describeAlarms.data.find(alarm => alarm.MetricName === filters.metricTransformations[0].metricName);
            if (alarms){
                helpers.addResult(results, 0,
                    'CloudWatch alarms are configured for the VPC Flow Logs', 
                    region);
                
            } else {
                helpers.addResult(results, 2,
                    'CloudWatch alarms are not configured for the VPC Flow Logs', region);
                
            }
                    
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
