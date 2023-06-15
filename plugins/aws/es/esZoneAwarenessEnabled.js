var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Zone Awareness Enabled',
    category: 'ES',
    domain: 'Databases',
    description: 'Ensure that Elasticsearch domains enable zone awareness',
    more_info: 'Enabling zone awareness improves the fault-tolerance for your ES domains by distributing the Elasticsearch nodes across multiple availability zones in the same AWS region and assures the cluster is highly available.',
    link: 'https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain/',
    recommended_action: 'Modify Elasticseach domain configuration and enable domain zone awareness.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var accountId =  helpers.addSource(cache, source, ['sts', 'getCallerIdentity', accRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for ES domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            for (var domain of listDomainNames.data) {
                if (!domain.DomainName) continue;
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(results, 3,
                        `Unable to query for ES domain config: ${helpers.addError(describeElasticsearchDomain)}`, region, resource);
                    continue;
                }

                if (describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig && 
                describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled &&
                describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled === true) {
                    helpers.addResult(results, 0,'Zone Awareness is enabled for ES domain', region, resource);
                } else {
                    helpers.addResult(results, 2,'Zone Awareness is not enabled for ES domain', region, resource);
                }

            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
