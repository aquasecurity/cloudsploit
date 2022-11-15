var expect = require('chai').expect;
var plugin = require('./kmsPublicAccess');

const cryptoKeys = [
    {
        "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek",
        "rotationPeriod": '7776000s',
        "purpose": "ENCRYPT_DECRYPT",
        "createTime": "2021-06-15T13:22:44.808595111Z"
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
        "createTime": "2021-06-15T14:05:00.127824829Z"
    }
];

const keyPolicies = [
    {
        "version": 1,
        "etag": "BwXZ3RM6WFs=",
        "bindings": [
            {
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": [
                    "allUsers",
                ]
            },
        ],
        "parent": {
            "id": "1231",
            "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
            "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek"
        }
    },
    {
        "version": 1,
        "etag": "BwXZ3RM6WFs=",
        "bindings": [
            {
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": [
                    "myserviceaccount@gmail.com",
                ]
            },
        ],
        "parent":  {
            "id": 1232,
            "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
            "name": "projects/test-project/locations/us-central1/keyRings/test-kr-1/cryptoKeys/test-cmek-1",
        }
    }
]

const createCache = (data, err, policyData, policyErr) => {
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
            },
            getIamPolicy: {
                'us-central1': {
                    err: policyErr,
                    data: policyData
                }
            }
        }
    }
};

describe('kmsPublicAccess', function () {
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
                null,
                ['error'],
                [],
                null
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
                [],
                null,
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown if unable to query IAM Policies for cryptographic keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query IAM Policies for Cryptographic Keys');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                cryptoKeys,
                null,
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no IAM Policies found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM Policies found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                cryptoKeys,
                null,
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if crypto key is publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cryptographic Key is publicly accessible');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [cryptoKeys[0]],
                null,
                [keyPolicies[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no IAM policies are found for cryptographic key', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM Policies found for cryptographic key');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [cryptoKeys[2]],
                null,
                [keyPolicies],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if cryptographic key is not publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cryptographic Key is not publicly accessible');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [cryptoKeys[1]],
                null,
                [keyPolicies[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });
    })
});