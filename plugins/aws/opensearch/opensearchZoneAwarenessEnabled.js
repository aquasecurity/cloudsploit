var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Zone Awareness Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that OpenSearch domains have zone awareness enabled.',
    more_info: 'To improve the fault-tolerance for your OpenSearch domain, ensure you enable zone awareness. It distributes the OpenSearch nodes across multiple availability zones in the same AWS region and assures the cluster is highly available.',
    link: 'https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain/',
    recommended_action: 'Modify OpenSearch domain configuration and enable domain zone awareness.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId =  helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.opensearch, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['opensearch', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for OpenSearch domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            for (var domain of listDomainNames.data) {
                if (!domain.DomainName) continue;

                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                var describeOpenSearchDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);
                
                if (!describeOpenSearchDomain ||
                    describeOpenSearchDomain.err ||
                    !describeOpenSearchDomain.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for OpenSearch domain config: ${helpers.addError(describeOpenSearchDomain)}`, region, resource);
                    continue;
                }

                if (describeOpenSearchDomain.data.DomainStatus && describeOpenSearchDomain.data.DomainStatus.ClusterConfig &&
                describeOpenSearchDomain.data.DomainStatus.ClusterConfig.ZoneAwarenessEnabled) {
                    helpers.addResult(results, 0,'OpenSearch domain has zone awareness enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,'OpenSearch domain does not have zone awareness enabled', region, resource);
                }

            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
