var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Vault Role Access',
    category: 'Backup',
    domain: 'Storage',
    description: 'Ensure that AWS Backup vaults are accessed through roles.',
    more_info: 'As a security best practice and to adhere to compliance standards, ensure only role level access is allowed on a Backup vault.',
    recommended_action: 'Modify access policy and give only role level access to backup vault.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault-access-policy.html',
    apis: ['Backup:listBackupVaults', 'Backup:getBackupVaultAccessPolicy'],

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
    
                if (!getBackupVaultAccessPolicy || getBackupVaultAccessPolicy.err || !getBackupVaultAccessPolicy.data || !getBackupVaultAccessPolicy.data.Policy) {
                    helpers.addResult(results, 3, `Unable to get Backup vault access policy: ${helpers.addError(getBackupVaultAccessPolicy)}`, region, resource);
                    continue;
                }
    
                var statements = helpers.normalizePolicyDocument(getBackupVaultAccessPolicy.data.Policy);
    
                if (!statements || !statements.length) {
                    helpers.addResult(results, 0,
                        'The Backup Vault policy does not have trust relationship statements',
                        region, resource);
                    continue;
                }
    
                let roleAccess = true;
                for (var statement of statements) {
                    var principalEval = helpers.globalPrincipal(statement.Principal);
                    if (principalEval && statement.Effect.toUpperCase() === 'ALLOW') {
                        roleAccess = false;
                        break;
                    }

                }
            
                if (!roleAccess) {
                    helpers.addResult(results, 2,
                        'Backup Vault does not have role level access only' , region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Backup Vault have role level access only', region, resource);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};