var expect = require('chai').expect;
var selectTrustedLaunch = require('./vmSecurityType');

const virtualMachines = [
    {
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm',
        'name': 'test-vm',
        'type': 'Microsoft.Compute/virtualMachines',
        'securityProfile': {
            'securityType': 'TrustedLaunch'
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/AQUA-RESOURCE_GROUP/providers/Microsoft.Compute/virtualMachines/test-vm-2',
        'name': 'test-vm-2',
        'type': 'Microsoft.Compute/virtualMachines',
        'securityProfile': {
            'securityType': 'NotTrustedLaunch'
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

describe('selectTrustedLaunch', function() {
    describe('run', function() {
        it('should give passing result if no virtual machines', function(done) {
            const cache = createCache([]);
            selectTrustedLaunch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual machines', function(done) {
            const cache = createCache(null);
            selectTrustedLaunch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Trusted Launch is selected', function(done) {
            const cache = createCache([virtualMachines[0]]);
            selectTrustedLaunch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('trustedlaunch is configured as security type for virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Trusted Launch is not selected', function(done) {
            const cache = createCache([virtualMachines[1]]);
            selectTrustedLaunch.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('trustedlaunch is not configured as security type for virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
