var expect = require('chai').expect;
var vmManagedDisks = require('./vmManagedDisks');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Linux',
                'name': 'test-vm-disk',
                'diskSizeGB': 4
            },
            'dataDisks': [
                {
                    'name': 'test-vm-data-disk',
                    'diskSizeGB': 4
                }
            ]
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Linux',
                'name': 'test-vm-disk',
                'managedDisk': {
                    'storageAccountType': 'Premium_LRS',
                    'id': '/subscriptions/123/resourceGroups/aqua-resource_group/providers/Microsoft.Compute/disks/test-vm-disk'
                },
                'diskSizeGB': 30
            },
            'dataDisks': [
                {
                    'name': 'test-vm-data-disk',
                    'managedDisk': {
                        'storageAccountType': 'Standard_LRS',
                        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/disks/test-vm-data-disk'
                    },
                    'diskSizeGB': 32,
                }
            ]
        }
    }
];

const createCache = (virtualMachines) => {
    let machine = {};
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

describe('vmManagedDisks', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            vmManagedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            vmManagedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtualMachines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual machine is using managed disks', function(done) {
            const cache = createCache([virtualMachines[1]]);
            vmManagedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual machine is configured to use Azure managed disks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual machine is not using managed disks', function(done) {
            const cache = createCache([virtualMachines[0]]);
            vmManagedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual machine is not configured to use Azure managed disks');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});