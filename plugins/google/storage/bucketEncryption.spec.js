var expect = require('chai').expect;
var plugin = require('./bucketEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
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
const createCache = (err, data, keysList, keysErr) => {
    return {
        buckets: {
            list: {
                'global': {
                    err: err,
                    data: data
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
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('bucketEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a bucket error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query storage buckets');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no storage buckets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage buckets found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if bucket has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        kind: "storage#bucket",
                        selfLink: "https://www.googleapis.com/storage/v1/b/test_bucket_spec1",
                        id: "test_bucket_spec1",
                        name: "test_bucket_spec1",
                        projectNumber: "dummy1",
                        metageneration: "3",
                        location: "US",
                        timeCreated: "2021-04-07T17:55:53.104Z",
                        updated: "2021-04-07T19:03:16.173Z",
                        locationType: "multi-region",
                        satisfiesPZS: false,
                        encryption: {
                            defaultKmsKeyName: 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2'
                        }
                    },
                    
                ],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if bucket does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        kind: "storage#bucket",
                        selfLink: "https://www.googleapis.com/storage/v1/b/test_bucket_spec1",
                        id: "test_bucket_spec1",
                        name: "test_bucket_spec1",
                        projectNumber: "dummy1",
                        metageneration: "3",
                        location: "US",
                        timeCreated: "2021-04-07T17:55:53.104Z",
                        updated: "2021-04-07T19:03:16.173Z",
                        locationType: "multi-region",
                        satisfiesPZS: false,
                    },
                ],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
    })
});
