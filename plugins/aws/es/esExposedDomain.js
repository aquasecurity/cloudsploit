var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Exposed Domain',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are not publicly exposed to all AWS accounts',
    more_info: 'ElasticSearch domains should not be publicly exposed to all AWS accounts.',
    link: 'https://aws.amazon.com/blogs/database/set-access-control-for-amazon-elasticsearch-service/',
    recommended_action: 'Update elasticsearch domain to set access control.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

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

            async.each(listDomainNames.data, function(domain, cb){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                var resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region, resource);
                    return cb();
                }

                var exposed;

                if (describeElasticsearchDomain.data.DomainStatus.AccessPolicies) {
                    var statements = helpers.normalizePolicyDocument(describeElasticsearchDomain.data.DomainStatus.AccessPolicies);

                    if (statements && statements.length) {
                        for (let statement of statements) {
                            var statementPrincipals = helpers.extractStatementPrincipals(statement);
                            exposed = statementPrincipals.find(principal => principal == '*');
                            if (exposed) break;
                        }

                        if (exposed) {
                            helpers.addResult(results, 2,
                                'Domain :' + domain.DomainName + ': is exposed to all AWS accounts',
                                region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                'Domain :' + domain.DomainName + ': is not exposed to all AWS accounts',
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'No statement found for access policies', region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'No access policy found', region, resource);
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