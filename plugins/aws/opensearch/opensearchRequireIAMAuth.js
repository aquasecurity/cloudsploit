var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch IAM Authentication',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures OpenSearch domains require IAM Authentication',
    more_info: 'OpenSearch domains can allow access without IAM authentication by having a policy that does not specify the principal or has a wildcard principal',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html',
    recommended_action: 'Configure the OpenSearch domain to have an access policy without a global principal or no principal',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

            if (!listDomainNames.data.length) {
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain) {
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region);
                } else {
                    if (!describeDomain.data.DomainStatus) {
                        helpers.addResult(results, 0,
                            'OpenSearch domain has no access policies', region, localDomain.ARN);
                    } else {
                        var localDomain = describeDomain.data.DomainStatus;

                        var policies = helpers.normalizePolicyDocument(localDomain.AccessPolicies);

                        if (!policies || !policies.length) {
                            helpers.addResult(results, 0,
                                'OpenSearch domain has no access policies', region, localDomain.ARN);
                        } else {
                            var found = [];
                            for (var p in policies) {
                                var policy = policies[p];
                                if (policy.Effect && policy.Effect == 'Allow' && !policy.Principal) {
                                    found.push(policy);
                                } else if (policy.Effect && policy.Effect == 'Allow' && helpers.globalPrincipal(policy.Principal, settings)) {
                                    found.push(policy);
                                }
                            }

                            if (found.length > 0) {
                                helpers.addResult(results, 2,
                                    'OpenSearch domain has policy that does not require IAM authentication', region, localDomain.ARN);
                            } else {
                                helpers.addResult(results, 0,
                                    'OpenSearch domain access policies require IAM authentication', region, localDomain.ARN);
                            }

                        }
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
