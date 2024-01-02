var expect = require('chai').expect;
var vmssApprovedExtensions = require('./vmssApprovedExtensions');

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
                'extensions': [
                    {
                        'name': 'errorextension',
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

describe('vmssApprovedExtensions', function() {
    describe('run', function() {
        it('should give passing result if no virtual machine scale sets', function(done) {
            const cache = createCache([]);
            vmssApprovedExtensions.run(cache, { vmss_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machine Scale Sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine scale sets', function(done) {
            const cache = createCache();
            vmssApprovedExtensions.run(cache, { vmss_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machine Scale Sets:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no VMSS Extensions found', function(done) {
            const cache = createCache([virtualMachineScaleSets[2]]);
            vmssApprovedExtensions.run(cache, { vmss_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No VMSS Extensions found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if installed extensions are approved by the organization', function(done) {
            const cache = createCache([virtualMachineScaleSets[0]]);
            vmssApprovedExtensions.run(cache, { vmss_approved_extensions: 'healthRepairExtension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('extension is approved by the organization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if installed extensions are not approved by the organization', function(done) {
            const cache = createCache([virtualMachineScaleSets[1]]);
            vmssApprovedExtensions.run(cache, { vmss_approved_extensions: 'healthRepairExtension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('extension is not approved by the organization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});