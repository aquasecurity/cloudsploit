var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Enable Audit Logs',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures the Audit Logs feature is enabled for all the Amazon OpenSearch domains',
    more_info: 'The Audit Logs feature allows you to log all user activity on your Amazon OpenSearch domains (clusters), including failed login attempts, and which users accessed certain indices, documents, or fields. ',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html',
    recommended_action: 'Ensure encryption-at-rest is enabled for all OpenSearch domains.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'],

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
                    'Unable to query for OpenSearch domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);
                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region);
                } else {
                    if (describeDomain.data &&
                        describeDomain.data.DomainStatus &&
                        describeDomain.data.DomainStatus.LogPublishingOptions &&
                        describeDomain.data.DomainStatus.LogPublishingOptions.AUDIT_LOGS &&
                        describeDomain.data.DomainStatus.LogPublishingOptions.AUDIT_LOGS.Enabled) {
                        helpers.addResult(results, 0,
                            'Audit Logs feature is enabled for OpenSearch domain', region, domain.DomainName);
                    } else {
                        helpers.addResult(results, 2,
                            'Audit Logs feature is not enabled for OpenSearch domain', region, domain.DomainName);
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
        var pluginName = 'opensearchEncryptedDomain';
        let defaultKeyDesc = 'Default master key that protects my OpenSearch data when no other key is defined';
        var domainNameArr = resource.split(':');
        var domain = domainNameArr[domainNameArr.length - 1].split('/')[1];

        // find the location of the domain needing to be remediated
        var domainLocation = domainNameArr[3];

        // add the location of the domain to the config
        config.region = domainLocation;

        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdForES) {
            params = {
                DomainName: domain,
                EncryptionAtRestOptions: {
                    'Enabled': true,
                    'KmsKeyId': settings.input.kmsKeyIdForES
                },
            };
        } else {
            let defaultKmsKeyId = helpers.getDefaultKeyId(cache, config.region, defaultKeyDesc);
            if (!defaultKmsKeyId) return callback(`No default OpenSearch key for the region ${config.region}`);
            params = {
                DomainName: domain,
                EncryptionAtRestOptions: {
                    'Enabled': true,
                    'KmsKeyId': defaultKmsKeyId
                },
            };
        }

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'Encryption': 'Disabled',
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
                'Action': 'ENCRYPTED',
                'OpenSearch': domain
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
