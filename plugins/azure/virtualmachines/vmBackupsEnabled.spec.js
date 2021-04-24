var expect = require('chai').expect;
var vmBackupsEnabled = require('./vmBackupsEnabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines'
    }
];

const recoveryVaults = [
    {
        'name': 'test-vault',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault',
        'type': 'Microsoft.RecoveryServices/vaults'
    }
];

const backupProtectedItems = [
    {
        'id': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm/protectedItems/VM;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm',
        'name': 'VM;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm',
        'type': 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',
        'virtualMachineId': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachines/test-vm',
        'policyId': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupPolicies/DailyPolicy'
    },
    {
        'id': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm-2/protectedItems/VM;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm-2',
        'name': 'VM;iaasvmcontainerv2;AQUA-RESOURCE-GROUP;test-vm-2',
        'type': 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',
        'virtualMachineId': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachines/test-vm-2',
        'policyId': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupPolicies/DailyPolicy'
    }
];

const createCache = (virtualMachines, recoveryVaults, backupProtectedItem) => {
    let machines = {};
    let vaults = {};
    let protectedItems = {};
    if (virtualMachines) {
        machines['data'] = virtualMachines;
    }
    if (recoveryVaults) {
        vaults['data'] = recoveryVaults;
        if (recoveryVaults.length && backupProtectedItem) {
            protectedItems[recoveryVaults[0].id] = {
                'data': backupProtectedItem
            };
        }
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machines
            }
        },
        recoveryServiceVaults: {
            listBySubscriptionId: {
                'eastus': vaults
            }
        },
        backupProtectedItems: {
            listByVault: {
                'eastus': protectedItems
            }
        }
    };
};

describe('vmBackupsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache();
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no backup recovery vaults', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No backup vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for backup recovery vaults', function(done) {
            const cache = createCache([virtualMachines[0]]);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for backup vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for backup product items', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]]);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for backups');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no backup product items found for virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[1]]);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure virtual machine does not have backups enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if backups are enabled', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[0]]);
            vmBackupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure virtual machine has backups enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});