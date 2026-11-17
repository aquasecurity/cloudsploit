var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Glue Crawler Security Configuration',
    category: 'Glue',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that AWS Glue crawlers use a security configuration.',
    more_info: 'A Glue security configuration defines how the data written by a crawler is encrypted: CloudWatch Logs, job bookmarks and S3 data. ' +
        'A crawler without a security configuration writes its logs and metadata without the encryption settings the organisation requires.',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html',
    recommended_action: 'Modify the Glue crawler to use a security configuration (the required one, when a name is configured for this plugin).',
    apis: ['Glue:getCrawlers', 'STS:getCallerIdentity'],
    settings: {
        glue_crawler_security_configuration: {
            name: 'Glue Crawler Required Security Configuration',
            description: 'Name of the security configuration every crawler must use. When empty, any security configuration is accepted.',
            regex: '^[A-Za-z0-9_-]*$',
            default: ''
        }
    },
    realtime_triggers: ['glue:CreateCrawler', 'glue:UpdateCrawler', 'glue:DeleteCrawler'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var requiredConfiguration = settings.glue_crawler_security_configuration || this.settings.glue_crawler_security_configuration.default;

        async.each(regions.glue, function(region, rcb) {
            var getCrawlers = helpers.addSource(cache, source, ['glue', 'getCrawlers', region]);

            if (!getCrawlers) return rcb();

            if (getCrawlers.err || !getCrawlers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Glue crawlers: ' + helpers.addError(getCrawlers), region);
                return rcb();
            }

            if (!getCrawlers.data.length) {
                helpers.addResult(results, 0, 'No Glue crawlers found', region);
                return rcb();
            }

            getCrawlers.data.forEach(function(crawler) {
                var resource = 'arn:' + awsOrGov + ':glue:' + region + ':' + accountId + ':crawler/' + crawler.Name;
                var configuration = crawler.CrawlerSecurityConfiguration;

                if (!configuration) {
                    helpers.addResult(results, 2, 'Glue crawler does not have a security configuration', region, resource);
                } else if (requiredConfiguration && configuration !== requiredConfiguration) {
                    helpers.addResult(results, 2,
                        'Glue crawler uses security configuration "' + configuration + '" instead of "' + requiredConfiguration + '"', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Glue crawler uses security configuration "' + configuration + '"', region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
