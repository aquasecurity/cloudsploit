const async = require('async');
const helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch TLS Version',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure OpenSearch domain is using the latest security policy to only allow TLS v1.2',
    more_info: 'OpenSearch domains should be configured to enforce TLS version 1.2 for all clients to ensure encryption of data in transit with updated features.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html',
    recommended_action: 'Update OpenSearch domain to set TLSSecurityPolicy to contain TLS version 1.2.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

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

            async.each(listDomainNames.data, function(domain, cb){
                if (!domain.DomainName) return cb();

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
                    return cb();
                }
                if (describeDomain.data.DomainStatus.DomainEndpointOptions &&
                    describeDomain.data.DomainStatus.DomainEndpointOptions.TLSSecurityPolicy &&
                    describeDomain.data.DomainStatus.DomainEndpointOptions.TLSSecurityPolicy == 'Policy-Min-TLS-1-2-2019-07') {
                    helpers.addResult(results, 0,
                        'OpenSearch domain is using TLS version 1.2', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'OpenSearch domain is not using TLS version 1.2', region, resource);
                }

                cb();
            }, function() {
                rcb();
            });

        }, function() {
            callback(null, results, source);
        });
    }
};