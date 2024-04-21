var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Logging Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures OpenSearch domains are configured to log data to CloudWatch',
    more_info: 'OpenSearch domains should be configured with logging enabled with logs sent to CloudWatch for analysis and long-term storage.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createdomain-configure-slow-logs.html',
    recommended_action: 'Ensure logging is enabled and a CloudWatch log group is specified for each OpenSearch domain.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.opensearch, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['opensearch', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for OpenSearch domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region);
                } else {
                    var localDomain = describeDomain.data.DomainStatus;
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
                                'OpenSearch domain logging is enabled and sending logs to CloudWatch', region, localDomain.ARN);
                        } else if (cloudWatchDisabled.length) {
                            let logStr = cloudWatchDisabled.join(', ').replace(/_/g, ' ');
                            helpers.addResult(results, 2,
                                `OpenSearch domain logging is enabled but logs are not configured to be sent to CloudWatch for: ${logStr}`, region, localDomain.ARN);
                        } else {
                            let logStr = logSelectionArr.join(', ').replace(/_/g, ' ');
                            helpers.addResult(results, 2,
                                `The following logs are not configured for the OpenSearch domain: ${logStr}`, region, localDomain.ARN);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'OpenSearch domain logging is not enabled', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
