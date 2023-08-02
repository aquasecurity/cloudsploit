var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Zone Awareness Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    description: 'Ensure that OpenSearch domains have zone awareness enabled',
    more_info: 'To improve the fault-tolerance for your OpenSearch domain, ensure you enable zone awareness. It distributes the OpenSearch nodes across multiple availability zones in the same AWS region and assures the cluster is highly available.',
    link: 'https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain/',
    recommended_action: 'Modify OpenSearch domain configuration and enable domain zone awareness.',
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
                    `Unable to query for ES domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            async.each(listDomainNames.data, function(domain, dcb){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(results, 3,
                        `Unable to query for ES domain config: ${helpers.addError(describeElasticsearchDomain)}`, region);
                    return dcb();
                }

                let resource = describeElasticsearchDomain.data.DomainStatus.ARN;

                if (describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig && 
                describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled &&
                describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig.ZoneAwarenessEnabled === true) {
                    helpers.addResult(results, 0,'Zone Awareness is enabled for ES domain', region, resource);
                } else {
                    helpers.addResult(results, 2,'Zone Awareness is not enabled for ES domain', region, resource);
                }

                dcb();
            }, function(){
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
