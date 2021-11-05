var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'XRay Encryption Enabled',
    category: 'XRay',
    domain: 'Application Integration',
    description: 'Ensures CMK-based encryption is enabled for XRay traces.',
    more_info: 'AWS XRay supports default encryption based on an AWS-managed KMS key as well as encryption using a customer managed key (CMK). For maximum security, the CMK-based encryption should be used.',
    link: 'https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html',
    recommended_action: 'Update XRay encryption configuration to use a CMK.',
    apis: ['XRay:getEncryptionConfig', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        xray_encryption_level: {
            name: 'X-Ray Minimum Encryption Level',
            description: 'In order (lowest to highest) sse=Default Encryption; awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },
    remediation_description: 'Encryption for the affected XRay traces will be enabled.',
    remediation_min_version: '202011271430',
    apis_remediate: ['XRay:getEncryptionConfig', 'KMS:listKeys', 'KMS:describeKey'],
    actions: {
        remediate: ['XRay:putEncryptionConfig'],
        rollback: ['XRay:putEncryptionConfig']
    },
    permissions: {
        remediate: ['xray:PutEncryptionConfig'],
        rollback: ['xray:PutEncryptionConfig']
    },
    remediation_inputs: {
        kmsKeyIdforXray: {
            name: '(Optional) XRay KMS Key ID',
            description: 'The KMS Key ID used for encryption',
            regex: '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-4[0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$',
            required: false
        }
    },
    realtime_triggers: ['xray:PutEncryptionConfig'],

    run: function(cache, settings, callback) {
        var config = {
            xray_encryption_level: settings.xray_encryption_level || this.settings.xray_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.xray_encryption_level);
        var currentEncryptionLevel;
        var currentEncryptionLevelString;

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.xray, function(region, rcb){
            var getEncryptionConfig = helpers.addSource(cache, source,
                ['xray', 'getEncryptionConfig', region]);

            if (!getEncryptionConfig) return rcb();

            if (getEncryptionConfig.err || !getEncryptionConfig.data) {
                helpers.addResult(results, 3,
                    'Unable to query for XRay encryption configuration: ' + helpers.addError(getEncryptionConfig), region);
                return rcb();
            }

            if (getEncryptionConfig.data &&
                getEncryptionConfig.data.Type &&
                getEncryptionConfig.data.Type == 'KMS' &&
                getEncryptionConfig.data.KeyId) {
                var kmsKeyId = getEncryptionConfig.data.KeyId.split('/')[1];

                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        `Unable to query KMS key: ${helpers.addError(describeKey)}`, region);
                    return rcb();
                }

                currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is greater than or equal to desired level ${config.xray_encryption_level}`, region);
                } else {
                    helpers.addResult(results, 2, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is less than desired level ${config.xray_encryption_level}`, region);
                }
            } else {
                currentEncryptionLevel = 1; //sse
                currentEncryptionLevelString = 'sse';
                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is greater than or equal to desired level ${config.xray_encryption_level}`, region);
                } else {
                    helpers.addResult(results, 2, `XRay is configured to use encryption at level ${currentEncryptionLevelString} which is less than desired level ${config.xray_encryption_level}`, region);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'xrayEncryptionEnabled';
        let defaultKeyDesc = 'Default master key that protects my X-Ray data when no other key is defined';

        var region = settings.region;

        // add the location of the xray to the config
        config.region = region;
        var params = {};

        // create the params necessary for the remediation
        if (settings.input &&
            settings.input.kmsKeyIdforXray) {
            params = {
                'Type': 'KMS',
                'KeyId': settings.input.kmsKeyIdforXray,
            };
        } else {
            let defaultKmsKeyId = helpers.getDefaultKeyId(cache, config.region, defaultKeyDesc);
            if (!defaultKmsKeyId) return callback(`No default X-Ray key for the region ${config.region}`);
            params = {
                'Type': 'KMS',
                'KeyId': defaultKmsKeyId
            };
        }

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][region] = {
            'Encryption': 'Default',
            'XRay': region
        };
        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][region] = action;
            remediation_file['remediate']['actions'][pluginName][region] = {
                'Action': 'KMSENCRYPTED',
                'XRay': region
            };

            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
