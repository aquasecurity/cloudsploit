var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Audit Logs Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that audit logs feature is enabled for OpenSearch domains.',
    more_info: 'Enabling audit logs feature allows to keep track of all user activity on Amazon OpenSearch domains (clusters), including failed login attempts, including authentication success and failures, index changes, and incoming search queries, enhancing security and compliance monitoring.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html',
    recommended_action: 'Modify Opensearch domain and enable audit logs.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.es, function(region, rcb) {
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

            listDomainNames.data.forEach(function(domain) {
                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
                
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3, 'Unable to query for OpenSearch domain config: ' + 
                        helpers.addError(describeDomain), region);
                    return;
                } else {
                    if (describeDomain.data.DomainStatus.LogPublishingOptions &&
                        describeDomain.data.DomainStatus.LogPublishingOptions.AUDIT_LOGS &&
                        describeDomain.data.DomainStatus.LogPublishingOptions.AUDIT_LOGS.Enabled) {
                        helpers.addResult(results, 0,
                            'Audit Logs feature is enabled for OpenSearch domain', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Audit Logs feature is not enabled for OpenSearch domain', region, resource);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
