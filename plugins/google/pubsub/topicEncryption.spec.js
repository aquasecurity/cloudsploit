var expect = require('chai').expect;
var plugin = require('./topicEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1",
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

const topics = [
    {
        name: "projects/test-dev-aqua/topics/test-topic",
    },
    {
        name: "projects/test-dev-aqua/topics/test-topic-2",
        kmsKeyName: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
    },
    {
        name: "projects/test-dev-aqua/topics/test-topic-2",
        kmsKeyName: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-1",
    }
];

const createCache = (listTopics, errTopics, listKeys, errKeys) => {
    return {
        topics: {
            list: {
                'global': {
                    err: errTopics,
                    data: listTopics
                }
            }
        },
        cryptoKeys: {
            list: {
                'global': {
                    err: errKeys,
                    data: listKeys
                }
            }
        }
    }
};

describe('topicEncryption', function () {
    describe('run', function () {
        it('should give passing result if no Pub/Sub topics found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Pub/Sub topics found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Pub/Sub topic is encrypted with desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [topics[1]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Pub/Sub topic is not encrypted with desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(
                [topics[0], topics[2]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Pub/Sub topics', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Pub/Sub topics');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
    })
});

