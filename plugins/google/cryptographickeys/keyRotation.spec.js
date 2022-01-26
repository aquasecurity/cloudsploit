var expect = require('chai').expect;
var plugin = require('./keyRotation');

const cryptoKeys = [
    {
        "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek",
        "primary": {
            "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek/cryptoKeyVersions/1",
            "protectionLevel": "HSM",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "generateTime": "2021-06-15T13:22:44.808595111Z"
        },
        "rotationPeriod": '7776000s',
        "purpose": "ENCRYPT_DECRYPT",
        "createTime": "2021-06-15T13:22:44.808595111Z",
        "versionTemplate": {
            "protectionLevel": "HSM",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"
        }
    },
    {
        "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek-1",
        "primary": {
            "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek-1/cryptoKeyVersions/1",
            "createTime": "2021-06-15T13:27:10.444152476Z",
            "protectionLevel": "SOFTWARE",
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "generateTime": "2021-06-15T13:27:10.444152476Z"
        },
    },
    {
        "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-csek-1",
        "purpose": "ENCRYPT_DECRYPT",
        "createTime": "2021-06-15T14:05:00.127824829Z",
        "versionTemplate": {
            "protectionLevel": "EXTERNAL",
            "algorithm": "EXTERNAL_SYMMETRIC_ENCRYPTION"
        }
    }
];

const createCache = (err, data) => {
    return {
        keyRings: {
            list: {
                'us-central1': {
                    data: [
                        {
                            'name': 'projects/test-project/locations/us-central1/keyRings/test-kr-1',
                            'createTime': '2021-06-14T13:58:29.562215224Z'
                        }
                    ]
                },
            }
        },
        cryptoKeys: {
            list: {
                'us-central1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('keyRotation', function () {
    describe('run', function () {
        it('should give unknown result if unable to query cryptographic keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query cryptographic keys');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no cryptographic keys found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No cryptographic keys found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if key rotation is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Key rotation is enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [cryptoKeys[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if key rotation is not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Key rotation is not enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [cryptoKeys[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
});