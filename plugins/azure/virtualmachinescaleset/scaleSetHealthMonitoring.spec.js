var expect = require('chai').expect;
var scaleSetHealthMonitoring = require('./scaleSetHealthMonitoring');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            'extensionProfile': {
                'extensions': [
                    {
                        'name': 'healthRepairExtension',
                        'properties': {
                            'autoUpgradeMinorVersion': false,
                            'publisher': 'Microsoft.ManagedServices',
                            'type': 'ApplicationHealthLinux',
                            'typeHandlerVersion': '1.0',
                            'settings': {
                                'protocol': 'http',
                                'port': 80,
                                'requestPath': '/'
                            }
                        }
                    }
                ]
            }
        }
    },
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            'extensionProfile': {
                'extensions': []
            }
        }
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

describe('scaleSetHealthMonitoring', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            scaleSetHealthMonitoring.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            scaleSetHealthMonitoring.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Virtual Machine Scale Set has health monitoring enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            scaleSetHealthMonitoring.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has health monitoring enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Virtual Machine Scale Set has health monitoring disabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            scaleSetHealthMonitoring.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set has health monitoring disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});