var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Access From IP Addresses',
    category: 'ES',
    description: 'Ensure only whitelisted IP addresses can access Amazon Elasticsearch domains.',
    more_info: 'ElasticSearch domains should only be accessible only from whitelisted IP addresses to avoid unauthorized access.',
    link: 'https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain/',
    recommended_action: 'Modify Elasticseach domain access policy to allow only known/whitelisted IP addresses.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    settings: {
        whitelisted_ip_addresses: {
            name: 'Whitelisted IP Addresses',
            description: 'Comma separated list of IP addresses allowed to access ES domains',
            regex: '/^(?=.*[^.]$)((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).?){4}/([1-9]|1[0-9]){1}$/',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var whitelisted_ip_addresses = settings.whitelisted_ip_addresses || this.settings.whitelisted_ip_addresses.default;

        if (!whitelisted_ip_addresses.length) return callback(null, results, source);

        whitelisted_ip_addresses = whitelisted_ip_addresses.split(',');

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for ES domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            async.each(listDomainNames.data, function(domain, dcb){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(results, 3,
                        `Unable to query for ES domain config: ${helpers.addError(describeElasticsearchDomain)}`, region);
                    return dcb();
                }

                var resource = describeElasticsearchDomain.data.DomainStatus.ARN;
                
                if (!describeElasticsearchDomain.data.DomainStatus.AccessPolicies) {
                    helpers.addResult(results, 0,
                        'No access policy found', region, resource);
                    return dcb();
                }

                var statements = helpers.normalizePolicyDocument(describeElasticsearchDomain.data.DomainStatus.AccessPolicies);
                var globalAccess = false;
                var intruderIps = [];

                for (var s in statements) {
                    var statement = statements[s];
                    if (!statement.Condition && statement.Principal && helpers.globalPrincipal(statement.Principal)) {
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
                        `ES domain "${domain.DomainName}" is publicly exposed`, region, resource);
                    return dcb();
                }

                if (!intruderIps.length) {
                    helpers.addResult(results, 0,
                        `ES domain "${domain.DomainName}" is not accessible from any unknown IP address`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `ES domain "${domain.DomainName}" is accessible from these unknown IP addresses: ${intruderIps.join(', ')}`,
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
