var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch HTTPS Only',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are configured to enforce HTTPS connections',
    more_info: 'ElasticSearch domains should be configured to enforce HTTPS connections for all clients to ensure encryption of data in transit.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html',
    recommended_action: 'Ensure HTTPS connections are enforced for all ElasticSearch domains.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    remediation_description: 'ES domain will be configured to enforce HTTPS.',
    remediation_min_version: '202011271930',
    apis_remediate: ['ES:listDomainNames'],
    remediation_inputs: {
        tlsSecurityPolicyforEs: {
            name: '(Optional) TLS Security Policy',
            description: 'The TLS Security Policy that needs to be applied to the HTTPS endpoint',
            regex: '^.*$',
            required: false
        }
    },
    actions: {
        remediate: ['ES:updateElasticsearchDomainConfig'],
        rollback: ['ES:updateElasticsearchDomainConfig']
    },
    permissions: {
        remediate: ['es:UpdateElasticsearchDomainConfig'],
        rollback: ['es:UpdateElasticsearchDomainConfig']
    },
    realtime_triggers: ['es:CreateElasticsearchDomain', 'es:UpdateElasticsearchDomainConfig'],

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
                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;

                    if (localDomain.DomainEndpointOptions &&
                        localDomain.DomainEndpointOptions.EnforceHTTPS) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to enforce HTTPS', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to enforce HTTPS', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'esHttpsOnly';
        var domainNameArr = resource.split(':');
        var domain = domainNameArr[domainNameArr.length - 1].split('/')[1];

        // find the location of the domain needing to be remediated
        var domainLocation = domainNameArr[3];

        // add the location of the domain to the config
        config.region = domainLocation;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.tlsSecurityPolicyforEs) {
            params = {
                DomainName: domain,
                DomainEndpointOptions: {
                    EnforceHTTPS: true,
                    TLSSecurityPolicy: settings.input.tlsSecurityPolicyforEs
                },
            };
        } else {
            params = {
                DomainName: domain,
                DomainEndpointOptions: {
                    EnforceHTTPS: true,
                    TLSSecurityPolicy: 'Policy-Min-TLS-1-2-2019-07'
                },
            };
        }

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Enforce HTTPS': 'Disabled',
            'ES': resource
        };
        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enforce HTTPS',
                'ES': domain
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
