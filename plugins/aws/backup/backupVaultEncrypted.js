var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Vault Encrypted',
    category: 'Backup',
    domain: 'Storage',
    description: 'Ensure that your Amazon Backup vaults are using AWS KMS Customer Master Keys instead of AWS managed-keys (i.e. default encryption keys).',
    more_info: 'When you encrypt AWS Backup using your own AWS KMS Customer Master Keys (CMKs) for enhanced protection, you have full control over who can use the encryption keys to access your backups.',
    recommended_action: 'Encrypt Backup Vault with desired encryption level',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault.html',
    apis: ['Backup:listBackupVaults', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        backup_vault_desired_encryption_level: {
            name: 'CodeArtifact Domain Target Encryption Level',
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
            desiredEncryptionLevelString: settings.backup_vault_desired_encryption_level || this.settings.backup_vault_desired_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.backup, function(region, rcb){
            var listBackupVaults = helpers.addSource(cache, source,
                ['backup', 'listBackupVaults', region]);

            if (!listBackupVaults) return rcb();

            if (listBackupVaults.err || !listBackupVaults.data) {
                helpers.addResult(results, 3,
                    `Unable to list Backup vaults: ${helpers.addError(listBackupVaults)}`, region);
                return rcb();
            }

            if (!listBackupVaults.data.length) {
                helpers.addResult(results, 0,
                    'No Backup vaults found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let backupVault of listBackupVaults.data) {
                if (!backupVault.BackupVaultArn) continue;

                let resource = backupVault.BackupVaultArn;
                if (backupVault.EncryptionKeyArn) {
                    var kmsKeyId = backupVault.EncryptionKeyArn.split('/')[1] ? backupVault.EncryptionKeyArn.split('/')[1] : backupVault.EncryptionKeyArn;

                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);  

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, backupVault.EncryptionKeyArn);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Backup vault is encrypted with ${currentEncryptionLevelString} \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Backup vault is encrypted with ${currentEncryptionLevelString} \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Backup vaults does not have encryption enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};