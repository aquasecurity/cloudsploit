var expect = require('chai').expect;
var noEmptyScaleSets = require('./noEmptyScaleSets');

const virtualMachineScaleSets = [
    {
        'name': 'test-ali-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'location': 'eastus'
    }
];

const virtualMachineScaleSetVMs = [
    {
        'name': 'test-vmss_0',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss/virtualMachines/0',
        'type': 'Microsoft.Compute/virtualMachineScaleSets/virtualMachines'
    }
];

const createCache = (virtualMachineScaleSets, virtualMachineScaleSetVMs) => {
    let scaleSet = {};
    let vm = {};
    if (virtualMachineScaleSets) {
        scaleSet['data'] = virtualMachineScaleSets;
        if (virtualMachineScaleSets.length > 0 && virtualMachineScaleSetVMs) {
            vm[virtualMachineScaleSets[0].id] = {
                data: virtualMachineScaleSetVMs
            };
        }
    }
    return {
        virtualMachineScaleSets: {
            listAll: {
                'eastus': scaleSet
            }
        },
        virtualMachineScaleSetVMs: {
            list: {
                'eastus': vm
            }
        }
    };
};

describe('noEmptyScaleSets', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([], null);
            noEmptyScaleSets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache(null, null);
            noEmptyScaleSets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for attached vm instances', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], null);
            noEmptyScaleSets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine scale set VM instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if virtual machine scale set has VM instances attached', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], [virtualMachineScaleSetVMs[1]]);
            noEmptyScaleSets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual machine scale set has VM instances attached');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if virtual machine scale set has no VM instances attached', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]], []);
            noEmptyScaleSets.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual machine scale set has no VM instances attached');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});