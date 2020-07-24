var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch IAM Authentication',
    category: 'ES',
    description: 'Ensures ElasticSearch domains require IAM Authentication',
    more_info: 'ElasticSearch domains can allow access without IAM authentication by having a policy that does not specify the principal or has a wildcard principal',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-ac.html',
    recommended_action: 'Configure the ElasticSearch domain to have an access policy without a global principal or no principal',
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
                    'Unable to query for ElasticSearch domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length) {
                helpers.addResult(results, 0, 'No ElasticSearch domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain) {
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ElasticSearch domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    if (!describeElasticsearchDomain.data.DomainStatus) {
                        helpers.addResult(results, 0,
                            'ElasticSearch domain has no access policies', region, localDomain.ARN);
                    } else {
                        var localDomain = describeElasticsearchDomain.data.DomainStatus;

                        var policies = helpers.normalizePolicyDocument(localDomain.AccessPolicies);

                        if (!policies || !policies.length) {
                            helpers.addResult(results, 0,
                                'ElasticSearch domain has no access policies', region, localDomain.ARN);
                        } else {
                            var found = [];
                            for (var p in policies) {
                                var policy = policies[p];
                                if (policy.Effect && policy.Effect == 'Allow' && !policy.Principal) {
                                    found.push(policy);
                                } else if (policy.Effect && policy.Effect == 'Allow' && helpers.globalPrincipal(policy.Principal)) {
                                    found.push(policy);
                                }
                            }

                            if (found.length > 0) {
                                helpers.addResult(results, 2,
                                    'ElasticSearch domain has policy that does not require IAM authentication', region, localDomain.ARN);
                            } else {
                                helpers.addResult(results, 0,
                                    'ElasticSearch domain access policies require IAM authentication', region, localDomain.ARN);
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
