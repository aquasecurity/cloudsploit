var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Access From IP Addresses',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure only whitelisted IP addresses can access Amazon OpenSearch domains.',
    more_info: 'OpenSearch domains should only be accessible only from whitelisted IP addresses to avoid unauthorized access.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-types-ip',
    recommended_action: 'Modify OpenSearch domain access policy to allow only known/whitelisted IP addresses.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    settings: {
        whitelisted_ip_addresses: {
            name: 'Whitelisted IP Addresses',
            description: 'A comma-separated list of trusted IP addresses allowed to access OpenSearch domains',
            regex: '/^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}/([1-9]|1[0-9]){1}$/',
            default: ''
        }
    },
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var whitelisted_ip_addresses = settings.whitelisted_ip_addresses || this.settings.whitelisted_ip_addresses.default;

        if (!whitelisted_ip_addresses.length) return callback(null, results, source);

        whitelisted_ip_addresses = whitelisted_ip_addresses.split(',');
        async.each(regions.opensearch, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['opensearch', 'listDomainNames', region]);
            if (!listDomainNames) return rcb();
            

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for OpenSearch domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            async.each(listDomainNames.data, function(domain, dcb){
                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(results, 3,
                        `Unable to query for OpenSearch domain config: ${helpers.addError(describeDomain)}`, region);
                    return dcb();
                }

                var resource = describeDomain.data.DomainStatus.ARN;
                
                if (!describeDomain.data.DomainStatus.AccessPolicies) {
                    helpers.addResult(results, 0,
                        'No access policy found', region, resource);
                    return dcb();
                }

                var statements = helpers.normalizePolicyDocument(describeDomain.data.DomainStatus.AccessPolicies);
                var globalAccess = false;
                var intruderIps = [];

                for (var s in statements) {
                    var statement = statements[s];
                    if (!statement.Condition && statement.Principal && helpers.globalPrincipal(statement.Principal, settings)) {
                        globalAccess = true;
                        break;
                    }

                    if (statement.Condition && statement.Condition.IpAddress &&
                        statement.Condition.IpAddress['aws:SourceIp'] && statement.Condition.IpAddress['aws:SourceIp'].length) {
                        statement.Condition.IpAddress['aws:SourceIp'].forEach(ip => {
                            if (whitelisted_ip_addresses.indexOf(ip) < 0) intruderIps.push(ip);
                        });
                    }
                }

                if (globalAccess) {
                    helpers.addResult(results, 2,
                        `OpenSearch domain "${domain.DomainName}" is publicly exposed`, region, resource);
                    return dcb();
                }

                if (!intruderIps.length) {
                    helpers.addResult(results, 0,
                        `OpenSearch domain "${domain.DomainName}" is not accessible from any unknown IP address`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `OpenSearch domain "${domain.DomainName}" is accessible from these unknown IP addresses: ${intruderIps.join(', ')}`,
                        region, resource);
                }

                dcb();
            }, function(){
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
