var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Dedicated Master Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that Amazon OpenSearch domains are using dedicated master nodes.',
    more_info: 'Using OpenSearch dedicated master nodes to separate management tasks from index and search requests will improve the clusters ability to manage easily different types of workload and make them more resilient in production.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html',
    recommended_action: 'Update the domain to use dedicated master nodes.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    realtime_triggers: ['opensearch:CreateDomain','opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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

            listDomainNames.data.forEach(domain => {
                if (!domain.DomainName) return;

                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region, resource);
                } else {
                    var localDomain = describeDomain.data.DomainStatus;

                    if (localDomain.ClusterConfig &&
                        localDomain.ClusterConfig.DedicatedMasterEnabled) {
                        helpers.addResult(results, 0,
                            'OpenSearch domain is configured to use dedicated master node', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'OpenSearch domain is not configured to use dedicated master node', region, resource);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};
