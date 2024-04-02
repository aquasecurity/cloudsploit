var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Vault Policies',
    category: 'Backup',
    domain: 'Storage',
    severity: 'High',
    description: 'Ensures Backup Vault policies are properly scoped with specific permissions.',
    more_info: 'Policies attached to Backup Vault should be scoped to least-privileged access and avoid the use of wildcards.',
    recommended_action: 'Ensure that all Backup Vault policies are scoped to specific services and API calls.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault-access-policy.html',
    apis: ['Backup:listBackupVaults', 'Backup:getBackupVaultAccessPolicy', 'STS:getCallerIdentity'],
    realtime_triggers: ['backup:CreateBackupVault','backup:DeleteBackupVault','backup:PutBackupVaultAccessPolicy','backup:DeleteBackupVaultAccessPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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

            for (let vault of listBackupVaults.data) {
                if (!vault.BackupVaultArn || !vault.BackupVaultName) continue;

                let resource = vault.BackupVaultArn;

                let getBackupVaultAccessPolicy = helpers.addSource(cache, source,
                    ['backup', 'getBackupVaultAccessPolicy', region, vault.BackupVaultName]);

                if (getBackupVaultAccessPolicy.err && getBackupVaultAccessPolicy.err.message === `Backup Vault ${resource} has no associated POLICY`) {
                    helpers.addResult(results, 0, 'Backup Vault has no associated policy attached', region, resource);
                } else if (!getBackupVaultAccessPolicy || getBackupVaultAccessPolicy.err || !getBackupVaultAccessPolicy.data || !getBackupVaultAccessPolicy.data.Policy) {
                    helpers.addResult(results, 3, `Unable to get Backup vault access policy: ${helpers.addError(getBackupVaultAccessPolicy)}`, region, resource);
                } else {
                    var statements = helpers.normalizePolicyDocument(getBackupVaultAccessPolicy.data.Policy);

                    if (!statements || !statements.length) {
                        helpers.addResult(results, 0,
                            'Backup Vault policy does not have trust relationship statements',
                            region, resource);
                        continue;
                    }

                    var actions = [];

                    for (var statement of statements) {
                        // Evaluates whether the effect of the statement is to "allow" access to the SNS
                        var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);

                        // Evaluates whether the principal is open to everyone/anonymous
                        var principalEval = helpers.globalPrincipal(statement.Principal, settings);

                        // Evaluates whether condition is scoped or global
                        let scopedCondition;
                        if (statement.Condition) scopedCondition = helpers.isValidCondition(statement, [], helpers.IAM_CONDITION_OPERATORS, false, accountId, settings);

                        if (!scopedCondition && principalEval && effectEval) {
                            if (statement.Action && typeof statement.Action === 'string') {
                                if (actions.indexOf(statement.Action) === -1) {
                                    actions.push(statement.Action);
                                }
                            } else if (statement.Action && statement.Action.length) {
                                for (var a in statement.Action) {
                                    if (actions.indexOf(statement.Action[a]) === -1) {
                                        actions.push(statement.Action[a]);
                                    }
                                }
                            }
                        }
                    }

                    if (actions.length) {
                        helpers.addResult(results, 2,
                            'Backup Vault policy allows global access to the action(s): ' + actions,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Backup Vault policy does not allow global access.',
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

