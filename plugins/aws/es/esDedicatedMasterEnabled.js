var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Dedicated Master Enabled',
    category: 'ES',
    description: 'Ensure that Amazon Elasticsearch domains are using dedicated master nodes.',
    more_info: 'Using Elasticsearch dedicated master nodes to separate management tasks from index and search requests will improve the clusters ability to manage easily different types of workload and make them more resilient in production.',
    link: 'http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html',
    recommended_action: 'Update the domain to use dedicated master nodes.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain', 'STS:getCallerIdentity'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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

            listDomainNames.data.forEach(domain => {
                if (!domain.DomainName) return;

                const resource = `arn:aws:es:${region}:${accountId}:domain/${domain.DomainName}`;
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
                } else {
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;

                    if (localDomain.ElasticsearchClusterConfig &&
                        localDomain.ElasticsearchClusterConfig.DedicatedMasterEnabled) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to use dedicated master node', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to use dedicated master node', region, resource);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};
