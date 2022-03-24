var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Deletion Protection Enabled',
    category: 'Backup',
    domain: 'Storage',
    severity: 'LOW',
    description: 'Ensure that an Amazon Backup vault access policy is configured to prevent the deletion of AWS backups in the backup vault.',
    more_info: 'With AWS Backup, you can assign policies to backup vaults and the resources they contain. Assigning policies allows you to do things like grant access to users to create backup plans and on-demand backups, but limit their ability to delete recovery points after they are created.',
    recommended_action: 'Enable access policy to prevent deletion of AWS Backup vaults and their resources.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault-access-policy.html',
    apis: ['Backup:listBackupVaults', 'Backup:getBackupVaultAccessPolicy' ],

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
                    `Unable to query for Backup vault list: ${helpers.addError(listBackupVaults)}`, region);
                return rcb();
            }

            if (!listBackupVaults.data.length) {
                helpers.addResult(results, 0, 'No Backup vaults found', region);
                return rcb();
            }

            for (let vault of listBackupVaults.data){
                if (!vault.BackupVaultArn || !vault.BackupVaultName) continue;
               
                let resource = vault.BackupVaultArn;

                let getBackupVaultAccessPolicy = helpers.addSource(cache, source,
                    ['backup', 'getBackupVaultAccessPolicy', region, vault.BackupVaultName]);

                if (getBackupVaultAccessPolicy && getBackupVaultAccessPolicy.err && getBackupVaultAccessPolicy.err.code &&
                        getBackupVaultAccessPolicy.err.code == 'ResourceNotFoundException') {
                    helpers.addResult(results, 2,
                        'Backup vault does not have any policy attached', region, resource);
                    continue;
                }
    
                if (!getBackupVaultAccessPolicy || getBackupVaultAccessPolicy.err || !getBackupVaultAccessPolicy.data) {
                    helpers.addResult(results, 3, `Unable to get Backup vault policy: ${helpers.addError(getBackupVaultAccessPolicy)}`, region, resource);
                    continue;
                }
    
                let statements = helpers.normalizePolicyDocument(getBackupVaultAccessPolicy.data.Policy);

                for (let statement of statements){  
                    if (statement.Action[0] === 'backup:DeleteRecoveryPoint' ) {
                        helpers.addResult(results, 0,
                            'the selected Amazon Backup vault is associated with an access policy, that have deletion protection configured',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'the selected Amazon Backup vault is associated with an access policy, that have no deletion protection configured',
                            region, resource);
                    }
                    
                }
                
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
