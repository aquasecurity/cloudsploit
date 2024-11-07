var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Public Service Domain',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures OpenSearch domains are created with private VPC endpoint options',
    more_info: 'OpenSearch domains can either be created with a public endpoint or with a VPC configuration that enables internal VPC communication. Domains should be created without a public endpoint to prevent potential public access to the domain.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/os-vpc.html',
    recommended_action: 'Configure the OpenSearch domain to use a VPC endpoint for secure VPC communication.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    settings: {
        allow_os_public_endpoint_if_ip_condition_policy: {
            name: 'Allow Public Only If IP Condition Policy or Restricted Principal',
            description: 'Allows public OpenSearch endpoints if set to true and if there is an IP Condition policy and/or a restricted non-star principal.',
            regex: '^(true|false)$',
            default: 'false'
        },
    },
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {
            allow_os_public_endpoint_if_ip_condition_policy: settings.allow_os_public_endpoint_if_ip_condition_policy || this.settings.allow_os_public_endpoint_if_ip_condition_policy.default
        };

        config.allow_os_public_endpoint_if_ip_condition_policy = (config.allow_os_public_endpoint_if_ip_condition_policy === 'true' || config.allow_os_public_endpoint_if_ip_condition_policy === true);

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

            listDomainNames.data.forEach(function(domain){
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region);
                } else {
                    var localDomain = describeDomain.data.DomainStatus;

                    // assume we have no bad policies
                    var validPolicy = true;

                    if (config.allow_os_public_endpoint_if_ip_condition_policy &&
                        localDomain.AccessPolicies) { // evaluate policies if the setting is enabled.
                        var policies = helpers.normalizePolicyDocument(localDomain.AccessPolicies);
                        if (!policies) policies = []; // if no policy document then no statements

                        for (var p in policies) {
                            var policy = policies[p];
                            var containsIpPolicy = policy.Condition && policy.Condition.IpAddress;

                            if (!containsIpPolicy && helpers.globalPrincipal(policy.Principal, settings)) {
                                validPolicy = false;
                            }
                        }
                    }

                    if (localDomain.VPCOptions &&
                        localDomain.VPCOptions.VPCId &&
                        localDomain.VPCOptions.VPCId.length) {
                        helpers.addResult(results, 0,
                            'OpenSearch domain is configured to use a VPC endpoint', region, localDomain.ARN);
                    } else {
                        if (config.allow_os_public_endpoint_if_ip_condition_policy) {
                            if (validPolicy) {
                                helpers.addResult(results, 0,
                                    'OpenSearch domain is configured to use a public endpoint, but is allowed since there are no public access policies.', region, localDomain.ARN);
                            } else {
                                helpers.addResult(results, 2,
                                    'OpenSearch domain is configured to use a public endpoint and has disallowed public access policies.', region, localDomain.ARN);
                            }
                        } else {
                            helpers.addResult(results, 2,
                                'OpenSearch domain is configured to use a public endpoint.', region, localDomain.ARN);
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
