var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Node To Node Encryption',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures OpenSearch domain traffic is encrypted in transit between nodes',
    more_info: 'OpenSearch domains should use node-to-node encryption to ensure data in transit remains encrypted using TLS 1.2.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html',
    recommended_action: 'Ensure node-to-node encryption is enabled for all OpenSearch domains.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain'],
    remediation_description: 'OpenSearch domain will be configured to use node-to-node encryption.',
    remediation_min_version: '202102152200',
    apis_remediate: ['OpenSearch:listDomainNames'],
    actions: {
        remediate: ['OpenSearch:updateDomainConfig'],
        rollback: ['OpenSearch:updateDomainConfig']
    },
    permissions: {
        remediate: ['opensearch:UpdateDomainConfig'],
        rollback: ['opensearch:UpdateDomainConfig']
    },
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

                    if (localDomain.NodeToNodeEncryptionOptions &&
                        localDomain.NodeToNodeEncryptionOptions.Enabled) {
                        helpers.addResult(results, 0,
                            'OpenSearch domain is configured to use node-to-node encryption', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2,
                            'OpenSearch domain is not configured to use node-to-node encryption', region, localDomain.ARN);
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
        var pluginName = 'opensearchNodeToNodeEncryption';
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
            'OpenSearch': resource
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
                'OpenSearch': domain
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
