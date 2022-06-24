var expect = require('chai').expect;
var performanceDiagnosticsEnabled = require('./performanceDiagnosticsEnabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Windows'
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Linux'
            }
        }
    }
];

const virtualMachineExtension = [
    {
        'name': 'AzurePerformanceDiagnostics',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm/extensions/AzurePerformanceDiagnostics',
        'type': 'Microsoft.Compute/virtualMachines/extensions',
        'provisioningState': 'Succeeded'
    },
    {
        'name': 'AzurePerformanceDiagnosticsLinux',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm/extensions/AzurePerformanceDiagnosticsLinux',
        'type': 'Microsoft.Compute/virtualMachines/extensions',
        'provisioningState': 'Succeeded'
    }

];

const createCache = (virtualMachines, virtualMachineExtension) => {
    let machine = {};
    let extension = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
        if (virtualMachines.length && virtualMachineExtension) {
            extension[virtualMachines[0].id] = {
                'data': virtualMachineExtension
            };
        }
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            }
        },
        virtualMachineExtensions: {
            list: {
                'eastus': extension
            }
        }
    };
};

describe('performanceDiagnosticsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache();
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no virtual machine extensions', function(done) {
            const cache = createCache([virtualMachines[1]], []);
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Performance Diagnostics is disabled on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine extensions', function(done) {
            const cache = createCache([virtualMachines[0]]);
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM Extensions');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Performance Diagnostics is enabled on the virtual machine for windows machine', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[0]]);
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Performance Diagnostics is enabled on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Performance Diagnostics is enabled on the virtual machine for linux machine', function(done) {
            const cache = createCache([virtualMachines[1]], [virtualMachineExtension[1]]);
            performanceDiagnosticsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Performance Diagnostics is enabled on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Performance Diagnostics is disabled on the virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[1]]);
            performanceDiagnosticsEnabled.run(cache, { vm_approved_extensions: 'Extension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Performance Diagnostics is disabled on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 
