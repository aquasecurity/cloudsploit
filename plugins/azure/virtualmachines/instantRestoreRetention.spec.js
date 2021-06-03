var expect = require('chai').expect;
var instantRestoreRetention = require('./instantRestoreRetention');

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

const backupPolicy = [
    {
        'id': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupPolicies/DailyPolicy',
        'name': 'DailyPolicy',
        'type': 'Microsoft.RecoveryServices/vaults/backupPolicies',
        'instantRPDetails': {},
        'instantRpRetentionRangeInDays': 5,
        'retentionPolicy': {
            'retentionPolicyType': 'LongTermRetentionPolicy',
            'dailySchedule': {
                'retentionDuration': {
                    'count': 30,
                    'durationType': 'Days'
                }
            }
        }
    },
    {
        'id': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupPolicies/DailyPolicy',
        'name': 'DailyPolicy',
        'type': 'Microsoft.RecoveryServices/vaults/backupPolicies',
        'instantRPDetails': {},
        'instantRpRetentionRangeInDays': 2,
        'retentionPolicy': {
            'retentionPolicyType': 'LongTermRetentionPolicy',
            'dailySchedule': {
                'retentionDuration': {
                    'count': 30,
                    'durationType': 'Days'
                }
            }
        }
    },
    {
        'id': '/Subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.RecoveryServices/vaults/test-vault/backupPolicies/HourlyLogBackup',
        'name': 'HourlyLogBackup',
        'type': 'Microsoft.RecoveryServices/vaults/backupPolicies',
        'subProtectionPolicy': []
    }
];

const createCache = (virtualMachines, recoveryVaults, backupProtectedItem, backupPolicies) => {
    let machines = {};
    let vaults = {};
    let protectedItems = {};
    let policy = {};
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

        if (recoveryVaults.length && backupPolicies) {
            policy[recoveryVaults[0].id] = {
                'data': backupPolicies
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
        },
        backupPolicies: {
            listByVault: {
                'eastus': policy
            }
        }
    };
};

describe('instantRestoreRetention', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache();
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no backup recovery vaults', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No backup recovery vaults found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for backup recovery vaults', function(done) {
            const cache = createCache([virtualMachines[0]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for backup recovery vaults');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for backup product items', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for backup retention policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for backup retention policies', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[0]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for backup retention policies');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no backup product items found for virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[1]], [backupPolicy[0]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No backup policies are configured for the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if instant restore backup retention period not found', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[0]], [backupPolicy[2]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No instant restore backup is configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if instant restore backup retention period is configured', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[0]], [backupPolicy[0]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM instant restore backups are configured to be retained for 5 of 5 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if backup retention period is not configured', function(done) {
            const cache = createCache([virtualMachines[0]], [recoveryVaults[0]], [backupProtectedItems[0]], [backupPolicy[1]]);
            instantRestoreRetention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM instant restore backups are configured to be retained for 2 of 5 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});