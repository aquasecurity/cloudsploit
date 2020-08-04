var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Logging Enabled',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are configured to log data to CloudWatch',
    more_info: 'ElasticSearch domains should be configured with logging enabled with logs sent to CloudWatch for analysis and long-term storage.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-slow-logs',
    recommended_action: 'Ensure logging is enabled and a CloudWatch log group is specified for each ElasticSearch domain.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;
                    var logSelectionArr = ['SEARCH_SLOW_LOGS', 'INDEX_SLOW_LOGS', 'ES_APPLICATION_LOGS'];
                    var cloudWatchDisabled = [];
                    if (localDomain.LogPublishingOptions &&
                        Object.keys(localDomain.LogPublishingOptions).length) {
                        for (let LogPublishingOptions in localDomain.LogPublishingOptions) {
                            let logGroups = localDomain.LogPublishingOptions[LogPublishingOptions];
                            if (!logGroups.CloudWatchLogsLogGroupArn &&
                                logGroups.Enabled) {
                                cloudWatchDisabled.push(LogPublishingOptions);
                            } else if (logGroups.CloudWatchLogsLogGroupArn &&
                                logGroups.Enabled) {
                                if (logSelectionArr.indexOf(LogPublishingOptions) > -1) {
                                    logSelectionArr.splice(logSelectionArr.indexOf(LogPublishingOptions), 1);
                                }
                            }
                        }
                        if (!logSelectionArr.length) {
                            helpers.addResult(results, 0,
                                'ES domain logging is enabled and sending logs to CloudWatch', region, localDomain.ARN);
                        } else if (cloudWatchDisabled.length) {
                            let logStr = cloudWatchDisabled.join(', ').replace(/_/g, ' ');
                            helpers.addResult(results, 2,
                                `ES domain logging is enabled but logs are not configured to be sent to CloudWatch for: ${logStr}`, region, localDomain.ARN);
                        }
                        else {
                            let logStr = logSelectionArr.join(', ').replace(/_/g, ' ');
                            helpers.addResult(results, 2,
                                `The following logs are not configured for the ES domain: ${logStr}`, region, localDomain.ARN);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain logging is not enabled', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
