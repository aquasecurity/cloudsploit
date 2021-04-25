var expect = require('chai').expect;
var oldVmDiskSnapshots = require('./oldVmDiskSnapshots');

let dateNow = new Date().toISOString();
let datePast = new Date(new Date().setDate(new Date().getDate() - 90)).toISOString();
const snapshots = [
    {
        'name': 'test-snapshot',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/snapshots/test-ali-ss',
        'type': 'Microsoft.Compute/snapshots',
        'location': 'eastus',
        'diskSizeGB': 30,
        'timeCreated': dateNow
    },
    {
        'name': 'test-snapshot',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/snapshots/test-ali-ss',
        'type': 'Microsoft.Compute/snapshots',
        'location': 'eastus',
        'diskSizeGB': 30,
        'timeCreated': datePast
    }
];

const createCache = (snapshots) => {
    let snapshot = {};
    if (snapshots) {
        snapshot['data'] = snapshots;
    }
    return {
        snapshots: {
            list: {
                'eastus': snapshot
            }
        }
    };
};

describe('oldVmDiskSnapshots', function() {
    describe('run', function() {
        it('should give passing result if no snapshots', function(done) {
            const cache = createCache([]);
            oldVmDiskSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing virtual machine disk snapshots');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for snapshots', function(done) {
            const cache = createCache(null);
            oldVmDiskSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk snapshots');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if snapshot is not older than desired limit', function(done) {
            const cache = createCache([snapshots[0]]);

            const createdDate = new Date(snapshots[0].timeCreated);
            const dateNow = new Date();
            const diffTime = Math.abs(dateNow - createdDate);
            const daysCreated = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

            oldVmDiskSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include(`VM disk snapshot is ${daysCreated} days older than 30 days desired limit`);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if snapshot is older than desired limit', function(done) {
            const cache = createCache([snapshots[1]]);

            const createdDate = new Date(snapshots[1].timeCreated);
            const dateNow = new Date();
            const diffTime = Math.abs(dateNow - createdDate);
            const daysCreated = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

            oldVmDiskSnapshots.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include(`VM disk snapshot is ${daysCreated} days older than 30 days desired limit`);
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});