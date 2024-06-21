var expect = require('chai').expect;
var vmssManagedIdentityEnabled = require('./vmssManagedIdentityEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        "identity": {
            "type": "SystemAssigned",
            "principalId": "123454",
            "tenantId": "1234548"
        },
    },
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
    }
];

const createCache = (virtualMachineScaleSets) => {
    let machine = {};
    if (virtualMachineScaleSets) {
        machine['data'] = virtualMachineScaleSets;
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('vmssManagedIdentityEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            vmssManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            vmssManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VM scale set has managed identity enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            vmssManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM scale set does not have managed identity enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            vmssManagedIdentityEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});