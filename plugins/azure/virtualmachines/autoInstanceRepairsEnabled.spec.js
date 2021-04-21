var expect = require('chai').expect;
var autoInstanceRepairsEnabled = require('./autoInstanceRepairsEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-ali-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'location': 'eastus',
        'automaticRepairsPolicy': {
            'enabled': true
        }
    },
    {
        'name': 'test-ali-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'location': 'eastus',
        'automaticRepairsPolicy': {
            'enabled': false
        }
    }
];

const createCache = (virtualMachineScaleSets) => {
    let scaleSet = {};
    if (virtualMachineScaleSets) {
        scaleSet['data'] = virtualMachineScaleSets;
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': scaleSet
            }
        }
    };
};

describe('autoInstanceRepairsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([], null);
            autoInstanceRepairsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache(null, null);
            autoInstanceRepairsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual machine scale set has automatic instance repair enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            autoInstanceRepairsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automatic instance repairs is enabled for virtual machine scale set');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual machine scale set dows not have automatic instance repair enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            autoInstanceRepairsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automatic instance repairs is not enabled for virtual machine scale set');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});