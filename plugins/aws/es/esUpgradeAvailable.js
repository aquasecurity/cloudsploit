var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Upgrade Available',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are running the latest service software',
    more_info: 'ElasticSearch domains should be configured to run the latest service software which often contains security updates.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-version-migration.html',
    recommended_action: 'Ensure each ElasticSearch domain is running the latest service software and update out-of-date domains.',
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
                    var currentVersion = localDomain.ServiceSoftwareOptions.CurrentVersion;
                    var upgradeVersion = localDomain.ServiceSoftwareOptions.NewVersion;
                    var upgradeAvailable = localDomain.ServiceSoftwareOptions.UpdateAvailable;
                    var upgradeStatus = localDomain.ServiceSoftwareOptions.UpdateStatus;

                    if (upgradeAvailable && upgradeStatus !== 'NOT_ELIGIBLE') {
                        helpers.addResult(results, 2,
                            'ES domain service software version: ' + currentVersion + ' is eligible for an upgrade to version: ' + upgradeVersion, region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 0,
                            'ES domain service software version: ' + currentVersion + ' is the latest eligible upgraded version', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
