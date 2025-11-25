var expect = require('chai').expect;
var scaleSetAdAuthEnabled = require('./scaleSetAdAuthEnabled');

const virtualMachineScaleSets = [
    {
        'name': 'test-vmss',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE-GROUP/providers/Microsoft.Compute/virtualMachineScaleSets/test-vmss',
        'type': 'Microsoft.Compute/virtualMachineScaleSets',
        'virtualMachineProfile': {
            'extensionProfile': {
                'extensions': [
                    {
                        'name': 'AADSSHLoginForLinux',
                        'properties': {
                            'autoUpgradeMinorVersion': false,
                            'publisher': 'Microsoft.ManagedServices',
                            'type': 'AADSSHLoginForLinux',
                            'typeHandlerVersion': '1.0',
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
                'extensions': [
                    {
                        'name': 'AADLoginForWindows',
                        'properties': {
                            'autoUpgradeMinorVersion': false,
                            'publisher': 'Microsoft.ManagedServices',
                            'type': 'AADLoginForWindows',
                            'typeHandlerVersion': '1.0',
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

describe('scaleSetAdAuthEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            scaleSetAdAuthEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            scaleSetAdAuthEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if linux Virtual Machine Scale Set has Entra ID authentication enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            scaleSetAdAuthEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has Entra ID authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give passing result if windows Virtual Machine Scale Set has Entra ID authentication enabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            scaleSetAdAuthEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine Scale Set has Entra ID authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Virtual Machine Scale Set has Entra ID authentication disabled', function(done) {
            const cache = createCache([virtualMachineScaleSets[2]]);
            scaleSetAdAuthEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine Scale Set has Entra ID authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});