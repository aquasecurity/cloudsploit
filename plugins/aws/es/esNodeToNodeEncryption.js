var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Node To Node Encryption',
    category: 'ES',
    domain: 'Databases',
    description: 'Ensures ElasticSearch domain traffic is encrypted in transit between nodes',
    more_info: 'ElasticSearch domains should use node-to-node encryption to ensure data in transit remains encrypted using TLS 1.2.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html',
    recommended_action: 'Ensure node-to-node encryption is enabled for all ElasticSearch domains.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    remediation_description: 'ES domain will be configured to use node-to-node encryption.',
    remediation_min_version: '202102152200',
    apis_remediate: ['ES:listDomainNames'],
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

                    if (localDomain.NodeToNodeEncryptionOptions &&
                        localDomain.NodeToNodeEncryptionOptions.Enabled) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to use node-to-node encryption', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to use node-to-node encryption', region, localDomain.ARN);
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
        var pluginName = 'esNodeToNodeEncryption';
        var domainNameArr = resource.split(':');
        var domain = domainNameArr[domainNameArr.length - 1].split('/')[1];

        // find the location of the domain needing to be remediated
        var domainLocation = domainNameArr[3];

        // add the location of the domain to the config
        config.region = domainLocation;

        // create the params necessary for the remediation
        var params = {
            DomainName: domain,
            NodeToNodeEncryptionOptions: {
                Enabled: true
            },
        };

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'NodeToNodeEncryption': 'Disabled',
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
                'Action': 'NodeToNodeENCRYPTED',
                'ES': domain
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
