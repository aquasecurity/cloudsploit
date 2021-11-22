var expect = require('chai').expect;
var plugin = require('./VMDisksCMKEncrypted');

const cryptoKeys = [
    {
        name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-1",
        primary: {
            name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1",
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
const disks = [
    {
        "kind": "compute#disk",
        "id": "5472446060006107254",
        "creationTimestamp": "2019-09-25T14:05:30.090-07:00",
        "name": "instance-3",
        "sizeGb": "10",
        "diskEncryptionKey": { "kmsKeyName": 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1' },
        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
        "status": "READY",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3"
    },
    {
        "kind": "compute#disk",
        "id": "5472446060006107254",
        "creationTimestamp": "2019-09-25T14:05:30.090-07:00",
        "name": "instance-3",
        "sizeGb": "10",
        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
        "status": "READY",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3"
    },

];


const createCache = (disks, disksError, keysList, keysErr) => {
    return {
        disks: {
                list: {
                    'us-central1-a': {
                        err: disksError,
                        data: disks
                    }
                }
        },
        cryptoKeys: {
            list: {
                'global': {
                    err: keysErr,
                    data: keysList
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


describe('VMDisksCMKEncrypted', function () {
    describe('run', function () {
        it('should give unknown result if a disk error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query compute disks');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                ['error'],
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no disks are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No compute disks found ');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache([], null, cryptoKeys, null);

            plugin.run(cache, {}, callback);
        });

        it('should pass if disk encryption level is equal to or greater than desired level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('greater than or equal to desired encryption level');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache([disks[0]], null, cryptoKeys, null);
            plugin.run(cache, {}, callback);
        });

        it('should fail if disk encryption level is less than desired level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('less than desired encryption level');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache([disks[1]], null, cryptoKeys, null);

            plugin.run(cache, {}, callback);
        })
        it('should fail if disk encryption level key is not found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('less than desired encryption level');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache([disks[0]], null, [], null);

            plugin.run(cache, {}, callback);
        })
    })
})