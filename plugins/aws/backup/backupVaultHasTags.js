var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Vault Has Tags',
    category: 'Backup',
    domain: 'Storage',
    severity: 'Low',
    description: 'Ensure that AWS Backup Vaults have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Backup Vault and add tags.', 
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault.html',
    apis: ['Backup:listBackupVaults', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['backup:CreateBackupVault','backup:DeleteBackupVault','backup:TagResource','backup:UntagResource'],
   

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
            helpers.checkTags(cache, 'Backup Vault', vaultARN, region, results, settings);
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};