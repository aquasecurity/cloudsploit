var expect = require('chai').expect;
var selectSecureBoot = require('./vmSecureBootEnabled');

const virtualMachines = [
    {
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'name': 'test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'securityProfile': {
            'uefiSettings': {
                'secureBootEnabled': true
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm-2',
        'name': 'test-vm-2',
        'type': 'Microsoft.Compute/virtualMachines',
        'securityProfile': {
            'uefiSettings': {
                'secureBootEnabled': false
            }
        }
    }
];

const createCache = (virtualMachines) => {
    let vm = {};
    if (virtualMachines) {
        vm['data'] = virtualMachines;
    }
    return {
        virtualMachines: {
            listAll: {
                'eastus': vm
            }
        }
    };
};

describe('selectSecureBoot', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            selectSecureBoot.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            selectSecureBoot.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Secure Boot is enabled', function(done) {
            const cache = createCache([virtualMachines[0]]);
            selectSecureBoot.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Secure Boot is enabled for virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Secure Boot is not enabled', function(done) {
            const cache = createCache([virtualMachines[1]]);
            selectSecureBoot.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Secure Boot is not enabled for virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
