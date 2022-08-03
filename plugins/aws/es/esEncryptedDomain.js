var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Encrypted Domain',
    category: 'ES',
    domain: 'Databases',
    description: 'Ensures ElasticSearch domains are encrypted with KMS',
    more_info: 'ElasticSearch domains should be encrypted to ensure data at rest is secured.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html',
    recommended_action: 'Ensure encryption-at-rest is enabled for all ElasticSearch domains.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    remediation_description: 'ES domain will be encrypted with KMS.',
    remediation_min_version: '202102151900',
    apis_remediate: ['ES:listDomainNames', 'KMS:listKeys', 'KMS:describeKey'],
    remediation_inputs: {
        kmsKeyIdForES: {
            name: '(Optional) KMS Key Id For ElasticSearch',
            description: 'KMS Key Id that will be used to encrypt ElasticSearch domain',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
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

                    if (localDomain.EncryptionAtRestOptions &&
                        localDomain.EncryptionAtRestOptions.Enabled) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to use encryption at rest', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to use encryption at rest', region, localDomain.ARN);
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
        var pluginName = 'esEncryptedDomain';
        let defaultKeyDesc = 'Default master key that protects my Elasticsearch data when no other key is defined';
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
            if (!defaultKmsKeyId) return callback(`No default ElasticSearch key for the region ${config.region}`);
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
                'Action': 'ENCRYPTED',
                'ES': domain
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
