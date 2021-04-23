var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Secrets Manager Encrypted Secrets',
    category: 'Secrets Manager',
    description: 'Ensures Secrets Manager Secrets are encrypted',
    more_info: 'Secrets Manager Secrets should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    recommended_action: 'Encrypt Secrets Manager Secrets',
    apis: ['SecretsManager:listSecrets', 'KMS:listKeys', 'KMS:describeKey'],
    link: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/data-protection.html',
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. Secrets Manager ' +
             'encryption should be enabled for all Secrets storing this type ' +
             'of data.'
    },
    settings: {
        secretsmanager_minimum_encryption_level: {
            name: 'Secrets Manager Secret Minimum Encryption Level',
            description: 'In order (lowest to highest) \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var desiredEncryptionLevelString = settings.secretsmanager_minimum_encryption_level || this.settings.secretsmanager_minimum_encryption_level.default;
        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(desiredEncryptionLevelString);

        async.each(regions.secretsmanager, (region, rcb) => {
            var listSecrets = helpers.addSource(cache, source, ['secretsmanager', 'listSecrets', region]);

            if (!listSecrets) return rcb();

            if (!listSecrets.data || listSecrets.err) {
                helpers.addResult(results, 3, `Unable to query for secrets: ${helpers.addError(listSecrets)}`, region);
                return rcb();
            }

            if (!listSecrets.data.length) {
                helpers.addResult(results, 0, 'No secrets found', region);
                return rcb();
            }

            for (let secret of listSecrets.data) {
                let encryptionLevel;
                let encryptionLevelString;

                if (!secret.KmsKeyId) encryptionLevel = 2; //awskms
                else {
                    const keyId = secret.KmsKeyId.startsWith('arn:aws:kms')
                        ? secret.KmsKeyId.split('/')[1]
                        : secret.KmsKeyId;

                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
                        continue;
                    }

                    encryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                }

                encryptionLevelString = helpers.ENCRYPTION_LEVELS[encryptionLevel];

                if (encryptionLevel < desiredEncryptionLevel) {
                    helpers.addResult(results, 2, `Secret configured to use ${encryptionLevelString} instead of ${desiredEncryptionLevelString}`, region, secret.ARN);
                } else {
                    helpers.addResult(results, 0, `Secret configured to use desired encryption ${encryptionLevelString}`, region, secret.ARN);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
