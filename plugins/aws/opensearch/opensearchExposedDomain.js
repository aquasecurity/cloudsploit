var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Exposed Domain',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures OpenSearch domains are not publicly exposed to all AWS accounts',
    more_info: 'OpenSearch domains should not be publicly exposed to all AWS accounts.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html',
    recommended_action: 'Update OpenSearch domain to set access control.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

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

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            async.each(listDomainNames.data, function(domain, cb){
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                var resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region, resource);
                    return cb();
                }

                var exposed;

                if (describeDomain.data.DomainStatus.AccessPolicies) {
                    var statements = helpers.normalizePolicyDocument(describeDomain.data.DomainStatus.AccessPolicies);

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