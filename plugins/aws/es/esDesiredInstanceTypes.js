var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Desired Instance Type',
    category: 'ES',
    domain: 'Databases',
    description: 'Ensure that all your Amazon Elasticsearch cluster instances are of given instance types.',
    more_info: 'Limiting the type of Amazon Elasticsearch cluster instances that can be provisioned will help address compliance requirements and prevent unexpected charges on the AWS bill.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html',
    recommended_action: 'Reconfigure the domain to have the desired instance types.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain', 'STS:getCallerIdentity'],
    settings: {
        es_desired_data_instance_type: {
            name: 'ES Data Instance Type',
            description: 'Instance type of ES data instances',
            regex: '^.*$',
            default: ''
        },
        es_desired_master_instance_type: {
            name: 'ES Master Instance Type',
            description: 'Instance type of ES dedicated master instances',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        const es_desired_data_instance_type = settings.es_desired_data_instance_type || this.settings.es_desired_data_instance_type.default;
        const es_desired_master_instance_type = settings.es_desired_master_instance_type || this.settings.es_desired_master_instance_type.default;

        if (!es_desired_data_instance_type.length && !es_desired_master_instance_type.length) return callback(null, results, source);
        
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

            for (const domain of listDomainNames.data) {
                if (!domain.DomainName) continue;

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
                    continue;
                }

                let disallowedDataInstanceTypes = [];
                let disallowedDedicatedInstanceTypes = [];

                if (describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig) {
                    const config = describeElasticsearchDomain.data.DomainStatus.ElasticsearchClusterConfig;

                    if (config.InstanceType && !es_desired_data_instance_type.includes(config.InstanceType)) disallowedDataInstanceTypes.push(config.InstanceType);
                    if (config.DedicatedMasterType && !es_desired_master_instance_type.includes(config.DedicatedMasterType)) disallowedDedicatedInstanceTypes.push(config.DedicatedMasterType);
                }

                if (disallowedDedicatedInstanceTypes.length && disallowedDataInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `ES domain is using ${disallowedDedicatedInstanceTypes.join(', ')} master instance(s) and ${disallowedDataInstanceTypes.join(', ')} data instance(s)`, 
                        region, resource);
                } else if (disallowedDedicatedInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `ES domain is using ${disallowedDedicatedInstanceTypes.join(', ')} master instance(s)`, 
                        region, resource);
                } else if (disallowedDataInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `ES domain is using ${disallowedDataInstanceTypes.join(', ')} data instance(s)`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'ES domain is using allowed master and node instance types',
                        region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};