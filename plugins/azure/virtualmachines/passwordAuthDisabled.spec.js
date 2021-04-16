var expect = require('chai').expect;
var passwordAuthDisabled = require('./passwordAuthDisabled');

const virtualMachines = [
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'adminUsername': 'aquauser',
            'linuxConfiguration': {
                'disablePasswordAuthentication': true
            }
        }
    },
    {
        'name': 'test-vm',
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'osProfile': {
            'computerName': 'test-vm',
            'linuxConfiguration': {
                'disablePasswordAuthentication': false
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

describe('passwordAuthDisabled', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            passwordAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            passwordAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtualMachines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Password authentication is disabled on virtual machine', function(done) {
            const cache = createCache([virtualMachines[0]]);
            passwordAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Password authentication is disabled on virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Password authentication is not disabled on virtual machine', function(done) {
            const cache = createCache([virtualMachines[1]]);
            passwordAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Password authentication is not disabled on virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});