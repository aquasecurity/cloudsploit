var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Encrypted Parameters',
    category: 'SSM',
    description: 'Ensures SSM Parameters are encrypted',
    more_info: 'SSM Parameters should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
    recommended_action: 'Recreate unencrypted SSM Parameters with Type set to SecureString.',
    apis: ['SSM:describeParameters', 'STS:getCallerIdentity', 'KMS:listAliases', 'KMS:listKeys', 'KMS:describeKey'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. SSM ' +
            'encryption should be enabled for all parameters storing this type ' +
            'of data.'
    },
    settings: {
        ssm_encryption_level: {
            name: 'SSM Minimum Encryption Level',
            description: 'In order (lowest to highest) \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        },
        allow_ssm_non_secure_strings: {
            name: 'Allow SSM Non-Secure Strings',
            description: 'Allow for non-secure strings to pass',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config = {
            ssm_encryption_level: settings.ssm_encryption_level || this.settings.ssm_encryption_level.default,
            allow_ssm_non_secure_strings: settings.allow_ssm_non_secure_strings || this.settings.allow_ssm_non_secure_strings.default
        };

        config.allow_ssm_non_secure_strings = (config.allow_ssm_non_secure_strings == 'true');

        var desiredEncryptionLevelString = settings.ssm_encryption_level || this.settings.ssm_encryption_level.default;
        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(desiredEncryptionLevelString);

        async.each(regions.ssm, function(region, rcb){
            var describeParameters = helpers.addSource(cache, source,
                ['ssm', 'describeParameters', region]);

            if (!describeParameters) return rcb();

            if (describeParameters.err || !describeParameters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Parameters: ${helpers.addError(describeParameters)}`, region);
                return rcb();
            }

            if (!describeParameters.data.length) {
                helpers.addResult(results, 0, 'No Parameters present', region);
                return rcb();
            }

            var aliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);

            if (!aliases || aliases.err || !aliases.data) {
                helpers.addResult(results, 3, `Unable to query KMS Aliases: ${helpers.addError(aliases)}`, region);
                return rcb();
            }

            async.each(describeParameters.data, function(param, pcb){
                var parameterName = param.Name.charAt(0) === '/' ? param.Name.substr(1) : param.Name;
                var arn = `arn:${awsOrGov}:ssm:${region}:${accountId}:parameter/${parameterName}`;

                if (param.Type != 'SecureString' && !config.allow_ssm_non_secure_strings) {
                    helpers.addResult(results, 2, 'Non-SecureString Parameters present', region, arn);
                    return pcb();
                }

                if (param.Type != 'SecureString' && config.allow_ssm_non_secure_strings) {
                    helpers.addResult(results, 0, 'Non-SecureString Parameters present but are allowed', region, arn);
                    return pcb();
                }

                var keyId;
                if (!param.KeyId) {
                    helpers.addResult(results, 2, 'SSM Parameters is not encrypted', region, arn);
                    return pcb();
                }

                if (param.KeyId.includes('alias')) {
                    var alias = aliases.data.find(a => a.AliasName === param.KeyId);
                    if (!alias || !alias.TargetKeyId) {
                        helpers.addResult(results, 3, `Unable to locate alias: ${param.KeyId} for SSM Parameter`, region, arn);
                        return pcb();
                    }
                    keyId = alias.TargetKeyId;
                } else {
                    keyId = param.KeyId.split('/')[1];
                }

                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3, `Unable to query KMS Key: ${keyId}`, region, arn);
                    return pcb();
                }

                var currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel < desiredEncryptionLevel) {
                    helpers.addResult(results, 2, 
                        `SSM Parameter is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level`,
                        region, arn);
                } else {
                    helpers.addResult(results, 0,
                        `SSM Parameter is encrypted to a minimum desired level of ${desiredEncryptionLevelString}`,
                        region, arn);
                }

                pcb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
