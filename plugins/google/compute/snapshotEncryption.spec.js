var expect = require('chai').expect;
var plugin = require('./snapshotEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2/cryptoKeyVersions/1",
            state: "DESTROYED",
            createTime: "2021-06-17T08:01:36.739860492Z",
            destroyEventTime: "2021-06-18T11:17:00.798768Z",
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
            generateTime: "2021-06-17T08:01:36.739860492Z",
        },
        purpose: "ENCRYPT_DECRYPT",
        createTime: "2021-06-17T08:01:36.739860492Z",
        nextRotationTime: "2021-09-14T19:00:00Z",
        rotationPeriod: "7776000s",
        versionTemplate: {
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
        },
    }
];

const snapshots = [
    {
        id: '11111',
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
    },
    {
        id: '22222',
        creationTimestamp: new Date(),
        name: 'snapshot-1',
        status: 'READY',
        sourceDisk: 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a/disks/disk-2',
        sourceDiskId: '7633933784896409327',
        diskSizeGb: '10',
        storageBytes: '0',
        storageBytesStatus: 'UP_TO_DATE',
        snapshotEncryptionKey: {
            kmsKeyName: 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2/cryptoKeyVersions/1'
          },
        selfLink: 'https://www.googleapis.com/compute/v1/projects/my-project-1/global/snapshots/snapshot-2',
        labelFingerprint: '42WmSpB8rSM=',
        storageLocations: ['us-central1'],
        downloadBytes: '1390',
        kind: 'compute#snapshot'
    }
];

const createCache = (snapshotData, error, keysErr, keysList) => {
    return {
       
        cryptoKeys: {
            list: {
                'global': {
                    err: keysErr,
                    data: keysList
                }
            }
        },
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
                    data: [{ name: 'testproj' }]
                }
            }
        }
    }
};

describe('snapshotEncryption', function () {
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
                null,
                null
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
                null,
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if disk snapshot has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [snapshots[1]],
                null,
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if disk snapshot does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [snapshots[0]],
                null,
                null,
                cryptoKeys
            );


            plugin.run(cache, {}, callback);
        })
    })
});