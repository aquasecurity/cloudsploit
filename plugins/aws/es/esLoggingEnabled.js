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

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.es, function (region, rcb) {
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
                    var logSources = Object.keys(localDomain.LogPublishingOptions || {})

                    if (!logSources.length) {
                        helpers.addResult(results, 2,
                            'ES domain logging is not enabled', region, localDomain.ARN);
                    }

                    logSources.forEach(function(source){
                        var logConfiguration = localDomain.LogPublishingOptions[source]

                        if (!logConfiguration.Enabled) {
                            helpers.addResult(results, 2,
                                'ES domain logging is disabled for ' + source, region, localDomain.ARN);
                        } else if (!logConfiguration.CloudWatchLogsLogGroupArn) {
                            helpers.addResult(results, 2,
                                'ES domain logging is enabled for ' + source + ' but logs are not configured to be sent to CloudWatch', region, localDomain.ARN);
                        } else {
                            helpers.addResult(results, 0,
                                'ES domain logging is enabled for ' + source + ' and sending logs to CloudWatch', region, localDomain.ARN);
                        }
                    });
                }
            });

            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};
