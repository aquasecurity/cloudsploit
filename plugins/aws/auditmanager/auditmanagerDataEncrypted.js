var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Audit Manager Data Encrypted',
    category: 'Audit Manager',
    domain: 'Management and Governance',
    description: 'Ensure that all data in Audit Manager is encrypted with desired encryption level.',
    more_info: 'All resource in AWS Audit Manager such as assessments, controls, frameworks, evidence are encrypted under a customer managed key or an AWS owned key, depending on your selected settings. ' +
        'If you don’t provide a customer managed key, AWS Audit Manager uses an AWS owned key to encrypt your content. ' +
        'Encrypt these resources using customer-managed keys in order to gain more granular control over encryption/decryption process.',
    recommended_action: 'Modify Audit Manager data encryption settings and choose desired encryption key for data encryption',
    link: 'https://docs.aws.amazon.com/audit-manager/latest/userguide/data-protection.html',
    apis: ['AuditManager:getSettings', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        auditmanager_data_encryption_level: {
            name: 'Audit Manager Data Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.auditmanager_data_encryption_level || this.settings.auditmanager_data_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        for (let region of regions.auditmanager) {
            var getSettings = helpers.addSource(cache, source,
                ['auditmanager', 'getSettings', region]);

            if (!getSettings) continue;

            if (getSettings.err && getSettings.err.message && getSettings.err.message.includes('Please complete AWS Audit Manager setup')) {
                helpers.addResult(results, 0,
                    'Audit Manager is not setp up for this region', region);
                continue;
            } else if (getSettings.err || !getSettings.data) {
                helpers.addResult(results, 3,
                    `Unable to query Audit Manager settings: ${helpers.addError(getSettings)}`, region);
                continue;
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                continue;
            }

            if (getSettings.data.kmsKey && getSettings.data.kmsKey.length) {
                if (getSettings.data.kmsKey.toUpperCase() == 'DEFAULT') {
                    currentEncryptionLevel = 2; //awskms
                } else {
                    var kmsKeyId = getSettings.data.kmsKey.split('/')[1] ? getSettings.data.kmsKey.split('/')[1] : getSettings.data.kmsKey;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, getSettings.data.kmsKey);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `Audit Manager data is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region);
                } else {
                    helpers.addResult(results, 2,
                        `Audit Manager data is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region);
                }
            } else {
                helpers.addResult(results, 3,
                    'Unable to retrieve encryption settings for Audit Manager data', region);
            }
        }

        callback(null, results, source);
    }
};
