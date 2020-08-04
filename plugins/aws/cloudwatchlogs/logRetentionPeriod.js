var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudWatch Log Retention Period',
    category: 'CloudWatchLogs',
    description: 'Ensures that the CloudWatch log retention period is set above a specified length of time.',
    more_info: 'Retention settings can be used to specify how long log events are kept in CloudWatch Logs. Expired log events get deleted automatically.',
    recommended_action: 'Ensure CloudWatch logs are retained for at least 90 days.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html',
    apis: ['CloudWatchLogs:describeLogGroups'],
    settings: {
        log_retention_in_days: {
            name: 'CloudWatch Log retention period minimum',
            description: 'Ensures CloudWatch Log groups have a retention no less than this value',
            regex: '^[0-9]*$',
            default: 90
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            log_retention_in_days: settings.log_retention_in_days || this.settings.log_retention_in_days.default
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.cloudwatchlogs, function(region, rcb){
            var describeLogGroups = helpers.addSource(cache, source, ['cloudwatchlogs', 'describeLogGroups', region]);

            if (!describeLogGroups || describeLogGroups.err ||
                !describeLogGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for CloudWatchLogs log groups: ' + helpers.addError(describeLogGroups), region);
                return rcb();
            }

            if (!describeLogGroups.data.length) {
                helpers.addResult(results, 0, 'There are no CloudWatch log groups in this region', region);
                return rcb()
            }

            for (let logGroup of describeLogGroups.data) {
                if (logGroup.retentionInDays) {
                    if (logGroup.retentionInDays < config.log_retention_in_days) {
                        helpers.addResult(results, 2,
                            'Log group retention period of ' + logGroup.retentionInDays + ' is less than required period of ' + config.log_retention_in_days, region,
                            logGroup.arn);
                    } else {
                        helpers.addResult(results, 0,
                            'Log group retention period of ' + logGroup.retentionInDays + ' is greater than or equal to the required period of ' + config.log_retention_in_days, region,
                            logGroup.arn);
                    }
                } else {
                    helpers.addResult(results, 2, 'Log group does not have a retention period', region, logGroup.arn);
                }
            }
            return rcb()
        }, function(){
            callback(null, results, source);
        });
    }
};
