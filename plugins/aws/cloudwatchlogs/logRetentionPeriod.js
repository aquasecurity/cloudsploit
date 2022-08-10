var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudWatch Log Retention Period',
    category: 'CloudWatchLogs',
    domain: 'Compliance',
    description: 'Ensures that the CloudWatch Log retention period is set above a specified length of time.',
    more_info: 'Retention settings can be used to specify how long log events are kept in CloudWatch Logs. Expired log events get deleted automatically.',
    recommended_action: 'Ensure CloudWatch logs are retained for at least 90 days.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html',
    apis: ['CloudWatchLogs:describeLogGroups'],
    settings: {
        minimum_log_retention_period: {
            name: 'CloudWatch Log Minimum Retention Period',
            description: 'If set, CloudWatch Logs log groups should have a retention setting greater or equal to this value',
            regex: '^[0-9]*$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            minimum_log_retention_period: parseInt(settings.minimum_log_retention_period || this.settings.minimum_log_retention_period.default)
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.cloudwatchlogs, function(region, rcb){
            var describeLogGroups = helpers.addSource(cache, source, ['cloudwatchlogs', 'describeLogGroups', region]);

            if (!describeLogGroups || describeLogGroups.err ||
                !describeLogGroups.data) {
                helpers.addResult(results, 3, `Unable to query CloudWatch Logs log groups: ${helpers.addError(describeLogGroups)}`, region);
                return rcb();
            }

            if (!describeLogGroups.data.length) {
                helpers.addResult(results, 0, 'No CloudWatch Logs log groups found', region);
                return rcb();
            }

            for (let logGroup of describeLogGroups.data) {
                if (logGroup.retentionInDays) {
                    if (logGroup.retentionInDays < config.minimum_log_retention_period) {
                        helpers.addResult(results, 2,
                            `Log group retention period of ${logGroup.retentionInDays} is less than required retention period of ${config.minimum_log_retention_period}`, region,
                            logGroup.arn);
                    } else {
                        helpers.addResult(results, 0,
                            `Log group retention period of ${logGroup.retentionInDays} is greater than or equal to the required retention period of ${config.minimum_log_retention_period}`, region,
                            logGroup.arn);
                    }
                } else {
                    helpers.addResult(results, 0, 'Log group retention period is set to never expire', region, logGroup.arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
