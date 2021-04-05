var expect = require('chai').expect;
var noUnattachedDisks = require('./noUnattachedDisks');

const disks = [
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'diskState': 'Attached'
    },
    {
        'name': 'test',
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/disks/test',
        'type': 'Microsoft.Compute/disks',
        'location': 'eastus',
        'diskState': 'Unattached'
    }
];

const createCache = (disks) => {
    const disk = {};
    if (disks) {
        disk['data'] = disks;
    }
    return {
        disks: {
            list: {
                'eastus': disk
            }
        }
    };
};

describe('noUnattachedDisks', function() {
    describe('run', function() {
        it('should give passing result if no disk volumes found', function(done) {
            const cache = createCache([]);
            noUnattachedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache(null);
            noUnattachedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk volumes:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk volume is attached to a virtual machine', function(done) {
            const cache = createCache([disks[0]]);
            noUnattachedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk volume is attached to a virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('disk volume is not attached to a virtual machine', function(done) {
            const cache = createCache([disks[1]]);
            noUnattachedDisks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk volume is not attached to a virtual machine');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});