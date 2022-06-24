var expect = require('chai').expect;
var vmAgentEnabled = require('./vmAgentEnabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'linuxConfiguration': {
                'provisionVMAgent': true,
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'linuxConfiguration': {
                'provisionVMAgent': false,
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'windowsConfiguration': {
                'provisionVMAgent': true,
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'windowsConfiguration': {
                'provisionVMAgent': false,
            }
        }
    }
];

const createCache = (virtualMachines) => {
    let machine = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            }
        }
    };
};

describe('vmAgentEnabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if vm agent is enabled for linux VM', function(done) {
            const cache = createCache([virtualMachines[0]]);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM Agent is enabled for this virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if vm agent is disabled for linux VM', function(done) {
            const cache = createCache([virtualMachines[1]]);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM Agent is not enabled for this virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if vm agent is enabled for windows VM', function(done) {
            const cache = createCache([virtualMachines[2]]);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM Agent is enabled for this virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if vm agent is disabled for windows VM', function(done) {
            const cache = createCache([virtualMachines[3]]);
            vmAgentEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM Agent is not enabled for this virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
