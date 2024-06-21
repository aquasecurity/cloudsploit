var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Upgrade Available',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures OpenSearch domains are running the latest service software',
    more_info: 'OpenSearch domains should be configured to run the latest service software which often contains security updates.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/version-migration.html',
    recommended_action: 'Ensure each OpenSearch domain is running the latest service software and update out-of-date domains.',
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
                    var currentVersion = localDomain.ServiceSoftwareOptions.CurrentVersion;
                    var upgradeVersion = localDomain.ServiceSoftwareOptions.NewVersion;
                    var upgradeAvailable = localDomain.ServiceSoftwareOptions.UpdateAvailable;
                    var upgradeStatus = localDomain.ServiceSoftwareOptions.UpdateStatus;

                    if (upgradeAvailable && upgradeStatus !== 'NOT_ELIGIBLE') {
                        helpers.addResult(results, 2,
                            'OpenSearch domain service software version: ' + currentVersion + ' is eligible for an upgrade to version: ' + upgradeVersion, region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 0,
                            'OpenSearch domain service software version: ' + currentVersion + ' is the latest eligible upgraded version', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
