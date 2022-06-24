var expect = require('chai').expect;
var vmEndpointProtection = require('./vmEndpointProtection');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Linux'
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'storageProfile': {
            'osDisk': {
                'osType': 'Windows'
            }
        }
    }
];

const virtualMachineExtension = [
    {
        'name': 'NetworkExtension',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm/extensions/NetworkExtension',
        'type': 'Microsoft.Compute/virtualMachines/extensions',
        'location': 'eastus',
        'autoUpgradeMinorVersion': true,
        'provisioningState': 'Succeeded',
        'type': 'NetworkWatcherAgentLinux',
        'settings': {}
    },
    {
        'name': 'AntimalwareExtension',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm/extensions/AntiMalwareExtension',
        'type': 'Microsoft.Compute/virtualMachines/extensions',
        'location': 'eastus',
        'autoUpgradeMinorVersion': true,
        'provisioningState': 'Succeeded',
        'type': 'IaaSAntimalware',
        'settings': {
            'AntimalwareEnabled': true
        }
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

describe('vmEndpointProtection', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache();
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no virtual machine extensions for windows image', function(done) {
            const cache = createCache([virtualMachines[1]], []);
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Microsoft VM does not offer endpoint protection');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if no virtual machine extensions for non windows image', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No VM Extensions found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine extensions', function(done) {
            const cache = createCache([virtualMachines[0]]);
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM Extensions');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Endpoint protection is installed on the virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[1]]);
            vmEndpointProtection.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Endpoint protection is installed on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if The Microsoft VM does not offer endpoint protection', function(done) {
            const cache = createCache([virtualMachines[1]], [virtualMachineExtension[0]]);
            vmEndpointProtection.run(cache, { vm_approved_extensions: 'TestExtension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Microsoft VM does not offer endpoint protection');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Endpoint protection is not installed on the virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[0]]);
            vmEndpointProtection.run(cache, { vm_approved_extensions: 'Extension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Endpoint protection is not installed on the virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 