var expect = require('chai').expect;
var plugin = require('./frequentlyUsedSnapshots');

const createCache = (snapshotData, error, imageData, imageError) => {
    return {
        snapshots: {
            list: {
                'global': {
                    data: snapshotData,
                    err: error
                }
            }
        },
       images: {
            list: {
                'global': {
                    data: imageData,
                    err: imageError
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

describe('frequentlyUsedSnapshots', function () {
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
                ['error'],
                [],
                null
            );

            plugin.run(cache, {snapshots_to_check: 'snapshot-1'}, callback);
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
                null,
                [],
                null
            );

            plugin.run(cache, {snapshots_to_check: 'snapshot-1'}, callback);
        });

        it('should give unknown if unable to query images', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for images');
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
                null,
                [],
                ['error']
            );

            plugin.run(cache, {snapshots_to_check: 'snapshot-1'}, callback);
        });

        it('should fail if snapshot does not have an image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('not have an image created');
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
                null,
                [],
                null
            );

            plugin.run(cache, {snapshots_to_check: 'snapshot-1'}, callback);
        })

        it('should pass if snapshot has an image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('an image created');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: '111151',
                        creationTimestamp: new Date(),
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
                null,
                [
                    {
                        id: '7777',
                        creationTimestamp: '2021-10-04T13:00:27.621-07:00',
                        name: 'image-1',
                        sourceType: 'RAW',
                        status: 'READY',
                        diskSizeGb: '10',
                        selfLink: 'https://www.googleapis.com/compute/v1/projects/my-project-1/global/images/image-1',
                        labelFingerprint: '42WmSpB8rSM=',
                        sourceSnapshot: 'https://www.googleapis.com/compute/v1/projects/my-project-1/global/snapshots/snapshot-1',
                        sourceSnapshotId: '111151',
                        storageLocations: ['us-central1'],
                        kind: 'compute#image'
                    }
                ]
            );

            plugin.run(cache, {snapshots_to_check: 'snapshot-1'}, callback);
        })

    })
});