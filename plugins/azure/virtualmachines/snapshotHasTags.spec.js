var expect = require('chai').expect;
var snapshotHasTags = require('./snapshotHasTags');
var helpers = require('../../../helpers/azure');

const snapshots = [
    {
        'name': 'test-snapshot',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/snapshots/test-ali-ss',
        'type': 'Microsoft.Compute/snapshots',
        'location': 'eastus',
        'diskSizeGB': 30,
        'tags': { 'key': 'value' }
    },
    {
        'name': 'test-snapshot',
        'id': '/subscriptions/123/resourceGroups/ALI-RECOURCE_GROUP/providers/Microsoft.Compute/snapshots/test-ali-ss',
        'type': 'Microsoft.Compute/snapshots',
        'location': 'eastus',
        'diskSizeGB': 30,
        'tags': {}
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

describe('snapshotHasTags', function() {
    describe('run', function() {
        it('should give passing result if no snapshots', function(done) {
            const cache = createCache([]);
            snapshotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No virtual machine disk snapshots found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for snapshots', function(done) {
            const cache = createCache(null);
            snapshotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for virtual machine disk snapshots');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if snapshot has tags associated', function(done) {
            const cache = createCache([snapshots[0]]);

            snapshotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM disk snapshot has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if snapshot does not have tags associated', function(done) {
            const cache = createCache([snapshots[1]]);

            snapshotHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM disk snapshot does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});