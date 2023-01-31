var expect = require('chai').expect;
var vmHasTags = require('./vmHasTags');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines'
    }
];

const virtualMachinesData = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'tags': { 'key': 'value'}
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
    }
];

const createCache = (virtualMachines, virtualMachineDetails) => {
    let machine = {};
    let machineDetails = {};
    if (virtualMachines) {
        machine['data'] = virtualMachines;
        if (virtualMachineDetails && virtualMachines.length) {
            machineDetails[virtualMachines[0].id]= {
                'data': virtualMachineDetails
            };
        }
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': machine
            },
            get: {
                'eastus': machineDetails
            }
        }
    };
};

describe('vmHasTags', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            vmHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            vmHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machine details', function(done) {
            const cache = createCache([virtualMachines[0]], null);
            vmHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('unable to query for virtual machine data');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VM has tags associated', function(done) {
            const cache = createCache([virtualMachines[0]], virtualMachinesData[0]);
            vmHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Machine has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM has does not have tags', function(done) {
            const cache = createCache([virtualMachines[0]], virtualMachinesData[1]);
            vmHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Machine does not have tags');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});