var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Instant Restore Backup Retention Period',
    category: 'Virtual Machines',
    description: 'Ensures that VM instant restore backup retention policy is configured to retain backups for the desired number of days.',
    more_info: 'Azure Backup provides independent and isolated backups to guard against unintended destruction of the data on your VMs. These backups should be retained for a specific amount of time to recover destroyed VM.',
    recommended_action: 'Configure virtual machine instant restore backup retention policy to retain backups for desired number of days',
    link: 'https://docs.microsoft.com/en-us/azure/backup/backup-instant-restore-capability',
    apis: ['virtualMachines:listAll', 'recoveryServiceVaults:listBySubscriptionId', 'backupProtectedItems:listByVault', 'backupPolicies:listByVault'],
    settings: {
        vm_instant_restore_retention_period: {
            name: 'VM Instant Restore Backup Retention Period',
            description: 'Number of days that a VM instant restore backup will be retained',
            regex: '^[1-5]$',
            default: '5'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            retentionPeriod: parseInt(settings.vm_instant_restore_retention_period || this.settings.vm_instant_restore_retention_period.default)
        };

        async.each(locations.virtualMachines, function(location, rcb) {
            const virtualMachines = helpers.addSource(cache, source,
                ['virtualMachines', 'listAll', location]);

            if (!virtualMachines) return rcb();

            if (virtualMachines.err || !virtualMachines.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual Machines: ' + helpers.addError(virtualMachines), location);
                return rcb();
            }

            if (!virtualMachines.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Machines found', location);
                return rcb();
            }

            const recoveryVaults = helpers.addSource(cache, source,
                ['recoveryServiceVaults', 'listBySubscriptionId', location]);

            if (!recoveryVaults || recoveryVaults.err || !recoveryVaults.data) {
                helpers.addResult(results, 3, 'Unable to query for backup recovery vaults: ' + helpers.addError(recoveryVaults), location);
                return rcb();
            }

            if (!recoveryVaults.data.length) {
                helpers.addResult(results, 2, 'No backup recovery vaults found', location);
                return rcb();
            }

            const vmPoliciesMap = new Map();
            const backupPoliciesMap = new Map();

            for (const vault of recoveryVaults.data) {
                const backupProtectedItems = helpers.addSource(cache, source,
                    ['backupProtectedItems', 'listByVault', location, vault.id]);

                if (!backupProtectedItems || backupProtectedItems.err || !backupProtectedItems.data) {
                    helpers.addResult(results, 3, 'Unable to query for backup retention policies : ' + helpers.addError(backupProtectedItems), location);
                    return rcb();
                }

                const backupPolicies = helpers.addSource(cache, source,
                    ['backupPolicies', 'listByVault', location, vault.id]);

                if (!backupPolicies || backupPolicies.err || !backupPolicies.data) {
                    helpers.addResult(results, 3, 'Unable to query for backup retention policies : ' + helpers.addError(backupPolicies), location);
                    return rcb();
                }

                for (const bpItem of backupProtectedItems.data) {
                    if (bpItem.virtualMachineId && vmPoliciesMap.get(bpItem.virtualMachineId.toLowerCase())) {
                        vmPoliciesMap.get(bpItem.virtualMachineId.toLowerCase()).push(bpItem.policyId);
                    } else if (bpItem.virtualMachineId) {
                        vmPoliciesMap.set(bpItem.virtualMachineId.toLowerCase(), []);
                        vmPoliciesMap.get(bpItem.virtualMachineId.toLowerCase()).push(bpItem.policyId);
                    }
                }

                for (const backupPolicy of backupPolicies.data) {
                    backupPoliciesMap.set(backupPolicy.id, backupPolicy);
                }
            }

            async.each(virtualMachines.data, function(virtualMachine, scb) {
                const vmPolicies = vmPoliciesMap.get(virtualMachine.id.toLowerCase());
                if (vmPolicies && vmPolicies.length) {
                    let retentionDays = 0;
                    for (const vmPolicy of vmPolicies) {
                        const backupPolicy = backupPoliciesMap.get(vmPolicy);

                        if (backupPolicy && backupPolicy.instantRpRetentionRangeInDays) {
                            retentionDays = backupPolicy.instantRpRetentionRangeInDays;
                        }
                    }

                    if (retentionDays === 0) {
                        helpers.addResult(results, 2, 'No instant restore backup is configured', location, virtualMachine.id);
                    } else if (retentionDays >= config.retentionPeriod) {
                        helpers.addResult(results, 0, `VM instant restore backups are configured to be retained for ${retentionDays} of ${config.retentionPeriod} days desired limit`, location, virtualMachine.id);
                    } else {
                        helpers.addResult(results, 2, `VM instant restore backups are configured to be retained for ${retentionDays} of ${config.retentionPeriod} days desired limit`, location, virtualMachine.id);
                    }
                } else {
                    helpers.addResult(results, 2, 'No backup policies are configured for the virtual machine', location, virtualMachine.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
