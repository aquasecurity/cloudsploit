var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Desired Instance Type',
    category: 'ES',
    description: 'Ensure that all your Amazon Elasticsearch cluster instances are of given instance types.',
    more_info: 'Limiting the type of Amazon Elasticsearch cluster instances that can be provisioned will help address compliance requirements and prevent unexpected charges on the AWS bill.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html',
    recommended_action: 'Reconfigure the domain to have the desired instance types.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain', 'STS:getCallerIdentity'],
    settings: {
        es_desired_instance_type: {
            name: 'Desired Instance Type',
            description: 'Instance type of ES data instances',
            regex: '^.*$',
            default: 't2.small.elasticsearch'
        },
        es_desired_master_instance_type: {
            name: 'Desired Dedicated Master Instance Type',
            description: 'Instance type of ES dedicated master instances',
            regex: '^.*$',
            default: 't2.medium.elasticsearch'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        const es_desired_instance_type = settings.es_desired_instance_type || this.settings.es_desired_instance_type.default;
        const es_desired_master_instance_type = settings.es_desired_master_instance_type || this.settings.es_desired_master_instance_type.default;

        if (!es_desired_instance_type.length && !es_desired_master_instance_type.length) return callback(null, results, source);
        
        const acctRegion = helpers.defaultRegion(settings);
        const accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        const awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.es, function(region, rcb) {
            const listDomainNames = helpers.addSource(cache, source,
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

            async.each(listDomainNames.data, function(domain, cb){
                const describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
                    return cb();
                }

                const localDomainStatus = describeElasticsearchDomain.data.DomainStatus;
                let disallowedInstanceTypes = [];
                if (localDomainStatus.ElasticsearchClusterConfig) {
                    const config = localDomainStatus.ElasticsearchClusterConfig;
                    if (config.InstanceType && !es_desired_instance_type.includes(config.InstanceType)) disallowedInstanceTypes.push(`${config.InstanceType} type for data node`);
                    if (config.DedicatedMasterType && !es_desired_master_instance_type.includes(config.DedicatedMasterType)) disallowedInstanceTypes.push(`${config.DedicatedMasterType} type for master node`);
                }

                let status = (disallowedInstanceTypes.length) ? 2 : 0;
                helpers.addResult(results, status,
                    `ES cluster is using ${status == 0 ? 'allowed instance types' : disallowedInstanceTypes.join(', ')}`,
                    region, resource);

                cb();
            }, function() {
                rcb();
            });

        }, function() {
            callback(null, results, source);
        });
    }
};