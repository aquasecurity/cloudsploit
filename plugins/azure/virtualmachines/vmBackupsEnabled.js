var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'VM Backups Enabled',
    category: 'Virtual Machines',
    description: 'Ensures that Azure virtual machine backups are enabled.',
    more_info: 'Azure Backup provides independent and isolated backups to guard against unintended destruction of the data on your VMs.',
    recommended_action: 'Enable Azure virtual machine backups',
    link: 'https://docs.microsoft.com/en-us/azure/backup/backup-azure-vms-introduction',
    apis: ['virtualMachines:listAll', 'recoveryServiceVaults:listBySubscriptionId', 'backupProtectedItems:listByVault'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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
                helpers.addResult(results, 3, 'Unable to query for backup vaults: ' + helpers.addError(recoveryVaults), location);
                return rcb();
            }

            if (!recoveryVaults.data.length) {
                helpers.addResult(results, 2, 'No backup vaults found', location);
                return rcb();
            }

            const vmPoliciesMap = new Map();

            for (const vault of recoveryVaults.data) {
                const backupProtectedItems = helpers.addSource(cache, source,
                    ['backupProtectedItems', 'listByVault', location, vault.id]);

                if (!backupProtectedItems || backupProtectedItems.err || !backupProtectedItems.data) {
                    helpers.addResult(results, 3, 'Unable to query for backups : ' + helpers.addError(backupProtectedItems), location);
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
            }

            for (const virtualMachine of virtualMachines.data) {
                const vmPolicies = vmPoliciesMap.get(virtualMachine.id.toLowerCase());

                let vmBackupsEnabled = false;
                if (vmPolicies && vmPolicies.length) {
                    vmBackupsEnabled = vmPolicies.some(policy => (policy && policy.length));
                }

                if (vmBackupsEnabled) {
                    helpers.addResult(results, 0, 'Azure virtual machine has backups enabled', location, virtualMachine.id);
                } else {
                    helpers.addResult(results, 2, 'Azure virtual machine does not have backups enabled', location, virtualMachine.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};