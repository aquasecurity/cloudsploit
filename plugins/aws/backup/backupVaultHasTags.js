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
    apis: ['Backup:listBackupVaults', 'ResourceGroupsTaggingAPI:getResources'],
   

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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
                helpers.addResult(results, 0,'No Backup vaults found', region);
                return rcb();
            }

            const vaultARN = [];
            for (let vault of listBackupVaults.data){
               if (!vault.BackupVaultArn) continue;

                vaultARN.push(vault.BackupVaultArn);
            }
            helpers.checkTags(cache, 'Backup Vault', vaultARN, region, results);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};