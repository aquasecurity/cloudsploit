var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Desired Instance Type',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that all your Amazon OpenSearch cluster instances are of given instance types.',
    more_info: 'Limiting the type of Amazon OpenSearch cluster instances that can be provisioned will help address compliance requirements and prevent unexpected charges on the AWS bill.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html',
    recommended_action: 'Reconfigure the domain to have the desired instance types.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    settings: {
        os_desired_data_instance_type: {
            name: 'OpenSearch Data Instance Type',
            description: 'Instance type of OpenSearch data instances',
            regex: '^.*$',
            default: ''
        },
        os_desired_master_instance_type: {
            name: 'OpenSearch Master Instance Type',
            description: 'Instance type of OpenSearch dedicated master instances',
            regex: '^.*$',
            default: ''
        }
    },
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:DeleteDomain'], 

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        const os_desired_data_instance_type = settings.os_desired_data_instance_type || this.settings.os_desired_data_instance_type.default;
        const os_desired_master_instance_type = settings.os_desired_master_instance_type || this.settings.os_desired_master_instance_type.default;

        if (!os_desired_data_instance_type.length && !os_desired_master_instance_type.length) return callback(null, results, source);
        
        const acctRegion = helpers.defaultRegion(settings);
        const accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        const awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.opensearch, function(region, rcb) {
            const listDomainNames = helpers.addSource(cache, source,
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

            for (const domain of listDomainNames.data) {
                if (!domain.DomainName) continue;

                const describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region, resource);
                    continue;
                }

                let disallowedDataInstanceTypes = [];
                let disallowedDedicatedInstanceTypes = [];

                if (describeDomain.data.DomainStatus.ClusterConfig) {
                    const config = describeDomain.data.DomainStatus.ClusterConfig;

                    if (config.InstanceType && !os_desired_data_instance_type.includes(config.InstanceType)) disallowedDataInstanceTypes.push(config.InstanceType);
                    if (config.DedicatedMasterType && !os_desired_master_instance_type.includes(config.DedicatedMasterType)) disallowedDedicatedInstanceTypes.push(config.DedicatedMasterType);
                }

                if (disallowedDedicatedInstanceTypes.length && disallowedDataInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `OpenSearch domain is using ${disallowedDedicatedInstanceTypes.join(', ')} master instance(s) and ${disallowedDataInstanceTypes.join(', ')} data instance(s)`, 
                        region, resource);
                } else if (disallowedDedicatedInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `OpenSearch domain is using ${disallowedDedicatedInstanceTypes.join(', ')} master instance(s)`, 
                        region, resource);
                } else if (disallowedDataInstanceTypes.length) {
                    helpers.addResult(results, 2,
                        `OpenSearch domain is using ${disallowedDataInstanceTypes.join(', ')} data instance(s)`,
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