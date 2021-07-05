var expect = require('chai').expect;
var premiumSsdDisabled = require('./premiumSsdDisabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'managedDisk': {
                    'storageAccountType': 'StandardSSD_LRS',
                    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_d88ee8681dbe4bd3bbbd52a1f8e46d7f'
                }
            },
            'dataDisks': []
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'managedDisk': {
                    'storageAccountType': 'Premium_LRS',
                    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_d88ee8681dbe4bd3bbbd52a1f8e46d7f'
                }
            },
            'dataDisks': []
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'managedDisk': {
                    'storageAccountType': 'StandardSSD_LRS',
                    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_d88ee8681dbe4bd3bbbd52a1f8e46d7f'
                }
            },
            'dataDisks': [
                {
                    'managedDisk': {
                        'storageAccountType': 'StandardSSD_LRS',
                        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-disk'
                    }
                }
            ]
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'managedDisk': {
                    'storageAccountType': 'Premium_LRS',
                    'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-vm_OsDisk_1_d88ee8681dbe4bd3bbbd52a1f8e46d7f'
                }
            },
            'dataDisks': [
                {
                    'managedDisk': {
                        'storageAccountType': 'Premium_LRS',
                        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test-disk'
                    }
                }
            ]
        }
    }
];

const createCache = (virtualMachines) => {
    const machine = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('premiumSsdDisabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines found', function(done) {
            const cache = createCache([]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if OS disk volume is not of Premium SSD type', function(done) {
            const cache = createCache([virtualMachines[0]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Attached OS disk volume is not of Premium SSD type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if OS disk volume is of Premium SSD type', function(done) {
            const cache = createCache([virtualMachines[1]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Attached OS disk volume is of Premium SSD type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing results if OS and data disk volumes is not of Premium SSD type', function(done) {
            const cache = createCache([virtualMachines[2]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Attached OS disk volume is not of Premium SSD type');

                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing results if OS and data disk volume is of Premium SSD type', function(done) {
            const cache = createCache([virtualMachines[3]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Attached OS disk volume is of Premium SSD type');
                
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('Attached data disk volume is of Premium SSD type');
                
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});