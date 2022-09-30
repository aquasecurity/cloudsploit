var expect = require('chai').expect;
var plugin = require('./snapshotLabelsAdded');

const createCache = (snapshotData, error) => {
    return {
        snapshots: {
            list: {
                'global': {
                    data: snapshotData,
                    err: error
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'test-proj'
                }
            }
        }
    }
};

describe('snapshotLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown if unable to query compute disk snapshots', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for disk snapshots');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if No compute disk snapshots found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No disk snapshots found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if snapshot does not have labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: '11111',
                        creationTimestamp: '2020-09-08T01:48:16.346-07:00',
                        name: 'snapshot-1',
                        status: 'READY',
                        sourceDisk: 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a/disks/disk-1',
                        sourceDiskId: '7633933784896409327',
                        diskSizeGb: '10',
                        storageBytes: '0',
                        storageBytesStatus: 'UP_TO_DATE',
                        selfLink: 'https://www.googleapis.com/compute/v1/projects/my-project-1/global/snapshots/snapshot-1',
                        labelFingerprint: '42WmSpB8rSM=',
                        storageLocations: ['us-central1'],
                        downloadBytes: '1390',
                        kind: 'compute#snapshot'
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if snapshot has labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for compute disk snapshot');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: '11111',
                        creationTimestamp: new Date(),
                        name: 'snapshot-1',
                        status: 'READY',
                        sourceDisk: 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a/disks/disk-1',
                        sourceDiskId: '7633933784896409327',
                        diskSizeGb: '10',
                        storageBytes: '0',
                        labels: {test: "test"},
                        storageBytesStatus: 'UP_TO_DATE',
                        selfLink: 'https://www.googleapis.com/compute/v1/projects/my-project-1/global/snapshots/snapshot-1',
                        labelFingerprint: '42WmSpB8rSM=',
                        storageLocations: ['us-central1'],
                        downloadBytes: '1390',
                        kind: 'compute#snapshot'
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});