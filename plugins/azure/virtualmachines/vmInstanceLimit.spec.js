var expect = require('chai').expect;
var vmInstanceLimit = require('./vmInstanceLimit');

const virtualMachines = [
    {
        'name': 'test-vm-1'
    },
    {
        'name': 'test-vm-1'
    },
    {
        'name': 'test-vm-1'
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

describe('vmInstanceLimit', function() {
    describe('run', function() {
        it('should give passing result if No existing Virtual Machines', function(done) {
            const cache = createCache([]);
            vmInstanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query Virtual Machines', function(done) {
            const cache = createCache();
            vmInstanceLimit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Virtual Machines');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if vm instances percentage are below the limits', function(done) {
            const cache = createCache(virtualMachines);
            const settings = {
                instance_limit_percentage_fail: 90,
                instance_limit_percentage_warn: 75,
                instance_limit: 5
            };
            vmInstanceLimit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Region contains 3 of 5 (60%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing results if number of vm instances has reached the fail limit', function(done) {
            const cache = createCache(virtualMachines);
            const settings = {
                instance_limit_percentage_fail: 50,
                instance_limit_percentage_warn: 35,
                instance_limit: 5
            };
            vmInstanceLimit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Region contains 3 of 5 (60%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give warn result if number of vm instances has reached the warn limit', function(done) {
            const cache = createCache(virtualMachines);
            const settings = {
                instance_limit_percentage_fail: 80,
                instance_limit_percentage_warn: 50,
                instance_limit: 5
            };
            vmInstanceLimit.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('Region contains 3 of 5 (60%) available instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 