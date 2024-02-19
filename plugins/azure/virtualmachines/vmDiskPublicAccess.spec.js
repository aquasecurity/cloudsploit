var expect = require('chai').expect;
var vmDiskPublicAccess = require('./vmDiskPublicAccess');

const disks = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk",
        "name": "test-disk",
        "location": "eastus",
        "networkAccessPolicy": "AllowAll"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk-private",
        "name": "test-disk-private",
        "location": "eastus",
        "networkAccessPolicy": "AllowPrivate"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Compute/disks/test-disk-none",
        "name": "test-disk-none",
        "location": "eastus",
        "networkAccessPolicy": "DenyAll"
    }
];

const createCache = (disks) => {
    return {
        disks: {
            list: {
                'eastus': {
                    data: disks
                }
            }
        }
    };
};

describe('vmDiskPublicAccess', function() {
    describe('run', function() {
        it('should give passing result if no disk volumes found', function(done) {
            const cache = createCache([]);
            vmDiskPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing disk volumes found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for disk volumes', function(done) {
            const cache = createCache(null);
            vmDiskPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk volumes:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if disk is publicly accessible', function(done) {
            const cache = createCache([disks[0]]);
            vmDiskPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk is privately accessible using private endpoints', function(done) {
            const cache = createCache([disks[1]]);
            vmDiskPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if disk is not publicly or privately accessible', function(done) {
            const cache = createCache([disks[2]]);
            vmDiskPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk is not publicly or privately accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
