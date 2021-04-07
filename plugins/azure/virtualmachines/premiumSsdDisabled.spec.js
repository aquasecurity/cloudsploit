var expect = require('chai').expect;
var premiumSsdDisabled = require('./premiumSsdDisabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines'
    }
];

const disks = [
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/disks/test',
        'managedBy': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'sku': {
            'name': 'StandardSSD_LRS',
            'tier': 'Standard'
        }
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/disks/test',
        'managedBy': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'sku': {
            'name': 'Premium_LRS',
            'tier': 'Premium'
        }
    }
];

const createCache = (virtualMachines, disks) => {
    const machine = {};
    const disk = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
    }
    if (disks) {
        disk['data'] = disks;
    }
    return {
        disks: {
            list: {
                'eastus': disk
            }
        },
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
            const cache = createCache([], []);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null, null);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no disk volumes found', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache([virtualMachines[0]], null);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk volumes');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk volume is of Standard SSD type', function(done) {
            const cache = createCache([virtualMachines[0]], [disks[0]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk volume is of standard SSD type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if disk volume is not of Standard SSD type', function(done) {
            const cache = createCache([virtualMachines[0]], [disks[1]]);
            premiumSsdDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk volume is not of standard SSD type');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});