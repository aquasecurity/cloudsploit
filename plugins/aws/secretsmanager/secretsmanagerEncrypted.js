var async = require('async');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    off: 0,
    awskms: 1,
    awscmk: 2,
    externalcmk: 3,
    cloudhsm: 4,
};

function getKeyEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
    title: 'SecretsManager Encrypted Secrets',
    category: 'SecretsManager',
    description: 'Ensures SecretsManager Secrets are encrypted',
    more_info: 'SecretsManager Secrets should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    recommended_action: 'Encrypt SecretsManager Secrets',
    apis: ['SecretsManager:listSecrets', 'SecretsManager:describeSecret', 'KMS:listKeys', 'KMS:describeKey'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. SecretsManager ' +
             'encryption should be enabled for all Secrets storing this type ' +
             'of data.'
    },
    settings: {
        secretsmanager_minimum_encryption_level: {
            name: 'SecretsManager Secret Minimum Encryption Level',
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

        var desiredEncryptionLevelString = settings.secretsmanager_minimum_encryption_level || this.settings.secretsmanager_minimum_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.secretsmanager_minimum_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for S3 Encryption Enforcement.');
            return callback(null, results, source);
        }

        async.each(regions.secretsmanager, (region, rcb) => {
            const listSecrets = helpers.addSource(cache, source, ['secretsmanager', 'listSecrets', region]);
            if (!listSecrets) return rcb();
            if (!listSecrets.data || listSecrets.err) {
                helpers.addResult(results, 3, `Unable to query for Secrets: ${helpers.addError(listSecrets)}`, region);
                return rcb();
            }
            if (!listSecrets.data.length) {
                helpers.addResult(results, 0, 'No secrets found', region);
                return rcb();
            }

            for (let secret of listSecrets.data) {
                let encryptionLevel;
                if (!secret.KmsKeyId) {
                    encryptionLevel = 'awskms';
                } else {
                    const keyId = secret.KmsKeyId.startsWith('arn:aws:kms')
                        ? secret.KmsKeyId.split('/')[1]
                        : secret.KmsKeyId;
                    const describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);
                    if (!describeKey || describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region, keyId);
                        continue;
                    }
                    encryptionLevel = getKeyEncryptionLevel(describeKey.data.KeyMetadata);
                }
                if (encryptionLevelMap[encryptionLevel] < encryptionLevelMap[desiredEncryptionLevelString]) {
                    helpers.addResult(results, 2, `Secret not configured to at least ${desiredEncryptionLevelString}, configured to ${encryptionLevel}`, region, secret.ARN);
                } else {
                    helpers.addResult(results, 0, `Secret configured to at least ${desiredEncryptionLevelString}, configured to ${encryptionLevel}`, region, secret.ARN);
                }
            }
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
