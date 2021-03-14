var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Glue Data Catalog CMK Encrypted',
    category: 'Glue',
    description: 'Ensures that AWS Glue has data catalog encryption enabled with KMS Customer Master Key (CMK).',
    more_info: 'AWS Glue should have data catalog encryption enabled with KMS Customer Master Key (CMK) instead of AWS-managed Key in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Modify Glue data catalog to use CMK instead of AWS-managed Key to encrypt Metadata',
    link: 'https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html',
    apis: ['Glue:getDataCatalogEncryptionSettings', 'KMS:listKeys', 'KMS:describeKey'],
    remediation_description: 'Glue data catalog Encryption for the affected regions will be enabled.',
    remediation_min_version: '202114032330',
    apis_remediate: ['Glue:getDataCatalogEncryptionSettings'],
    remediation_inputs: {
        kmsKeyArnforDataCatalog: {
            name: '(Mandatory) KMS Key Arn',
            description: 'The KMS Key Arn used for encryption',
            regex: '^arn:(aws|aws-cn|aws-us-gov):(kms):.+',
            required: true
        }
    },
    actions: {
        remediate: ['Glue:putDataCatalogEncryptionSettings'],
        rollback: ['Glue:putDataCatalogEncryptionSettings']
    },
    permissions: {
        remediate: ['glue:PutDataCatalogEncryptionSettings'],
        rollback: ['glue:PutDataCatalogEncryptionSettings']
    },
    realtime_triggers: ['glue:PutDataCatalogEncryptionSettings'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.glue, function(region, rcb){
            var getDataCatalogEncryptionSettings = helpers.addSource(cache, source,
                ['glue', 'getDataCatalogEncryptionSettings', region]);

            if (!getDataCatalogEncryptionSettings) return rcb();

            if (getDataCatalogEncryptionSettings.err || !getDataCatalogEncryptionSettings.data) {
                helpers.addResult(results, 3,
                    `Unable to query Glue data catalog encryption settings: ${helpers.addError(getDataCatalogEncryptionSettings)}`, region);
                return rcb();
            }

            var encryptionSettings = getDataCatalogEncryptionSettings.data;

            if (encryptionSettings && encryptionSettings.EncryptionAtRest &&
                encryptionSettings.EncryptionAtRest.CatalogEncryptionMode &&
                encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId &&
                encryptionSettings.EncryptionAtRest.CatalogEncryptionMode.toUpperCase() !== 'DISABLED') {

                var kmsKeyId = encryptionSettings.EncryptionAtRest.SseAwsKmsKeyId.split('/')[1];

                var describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, kmsKeyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                        region, kmsKeyId);
                    return rcb();
                }

                if (helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS) == 3) {
                    helpers.addResult(results, 0,
                        'Glue data catalog has encryption at-rest enabled for metadata using Customer Master Key',
                        region);
                } else {
                    helpers.addResult(results, 2,
                        'Glue data catalog has encryption at-rest enabled for metadata using AWS-managed key',
                        region);
                }
            } else {
                helpers.addResult(results, 2,
                    'Glue data catalog does not have encryption at-rest enabled for metadata',
                    region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },

    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'dataCatalogCmkEncrypted';

        var region = settings.region;

        config.region = region;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforDataCatalog) {
            params = {
                DataCatalogEncryptionSettings: {
                    EncryptionAtRest: {
                        CatalogEncryptionMode: 'SSE-KMS',
                        SseAwsKmsKeyId: settings.input.kmsKeyIdforDataCatalog
                    }
                }
            };
        } else {
            return callback('KMS key arn is mandatory to CMK encrypt Glue data catalog');
        }

        var remediation_file = settings.remediation_file;

        remediation_file['pre_remediate']['actions'][pluginName][region] = {
            'DataCatalogCMKEncryption': 'Disabled',
            'Glue': region
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
                'Action': 'DATA_CATALOG_CMK_ENCRYPTED',
                'Glue': region
            };
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};