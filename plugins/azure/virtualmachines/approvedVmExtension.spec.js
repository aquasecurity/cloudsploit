var expect = require('chai').expect;
var approvedVmExtension = require('./approvedVmExtension');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines'
    }
];

const virtualMachineExtension = [
    {
        'name': 'TestExtension',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm/extensions/TestExtension',
        'type': 'Microsoft.Compute/virtualMachines/extensions'
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

describe('approvedVmExtension', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            approvedVmExtension.run(cache, { vm_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache();
            approvedVmExtension.run(cache, { vm_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no virtual machine extensions', function(done) {
            const cache = createCache([virtualMachines[0]], []);
            approvedVmExtension.run(cache, { vm_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No VM Extensions found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine extensions', function(done) {
            const cache = createCache([virtualMachines[0]]);
            approvedVmExtension.run(cache, { vm_approved_extensions: 'ext' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM Extensions');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if vm extension is approved', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[0]]);
            approvedVmExtension.run(cache, { vm_approved_extensions: 'TestExtension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Installed extensions are approved by the organization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if vm extension is not approved', function(done) {
            const cache = createCache([virtualMachines[0]], [virtualMachineExtension[0]]);
            approvedVmExtension.run(cache, { vm_approved_extensions: 'Extension' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Installed extensions are not approved by the organization');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});