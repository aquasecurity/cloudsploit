var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Version',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures OpenSearch domains are using the latest engine version.',
    more_info: 'OpenSearch domains should be upgraded to the latest version for optimal performance and security.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html',
    recommended_action: 'Update OpenSearch domain to set to latest engine version.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 

    run:function(cache, settings, callback) {
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
                    var currentVersion = localDomain && localDomain.EngineVersion? localDomain.EngineVersion: '';

                    if ((currentVersion.includes('Elasticsearch') && currentVersion.includes('7.10')) || (currentVersion.includes('OpenSearch') && currentVersion.includes('2.5'))) {
                        helpers.addResult(results, 0, 
                            'OpenSearch domain is running the latest version', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2, 
                            'OpenSearch domain should be upgraded to latest version', region, localDomain.ARN);
                    }
                } 
                       
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

