var expect = require('chai').expect;
var plugin = require('./modelEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev/locations/us-central1/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev/locations/us-central1/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1",
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
const models = [
    {
        "name": 'projects/11111/locations/us-central1/models/3333333',
        "displayName": 'untitled_1706619456701',
        "supportedDeploymentResourcesTypes": ['AUTOMATIC_RESOURCES'],
        "supportedInputStorageFormats": ['jsonl'],
        "supportedOutputStorageFormats": ['jsonl'],
        "createTime": '2024-01-30T13:09:20.818657Z',
        "updateTime": '2024-01-31T06:06:12.979751Z',
        "etag": 'bbbbbbbbb',
        "versionId": '1',
        "versionAliases": ['default'],
        "versionCreateTime": '2024-01-30T13:09:20.818657Z',
        "versionUpdateTime": '2024-01-31T03:38:17.129540Z',
        "modelSourceInfo": { "sourceType": 'AUTOML' },
        "encryptionSpec": {
            "kmsKeyName": 'projects/test-dev/locations/us-central1/keyRings/test-kr/cryptoKeys/test-key-2'
        }
    },
    {
        "name": 'projects/11111/locations/us-central1/models/11111',
        "displayName": 'untitled_1706619456701',
        "supportedDeploymentResourcesTypes": ['AUTOMATIC_RESOURCES'],
        "supportedInputStorageFormats": ['jsonl'],
        "supportedOutputStorageFormats": ['jsonl'],
        "createTime": '2024-01-30T13:09:20.818657Z',
        "updateTime": '2024-01-31T06:06:12.979751Z',
        "etag": 'bbbbbbbbb',
        "versionId": '1',
        "versionAliases": ['default'],
        "versionCreateTime": '2024-01-30T13:09:20.818657Z',
        "versionUpdateTime": '2024-01-31T03:38:17.129540Z',
        "modelSourceInfo": { "sourceType": 'AUTOML' }
    },
];

const createCache = (err, data, keysErr, keysList) => {
    return {
        vertexAI: {
            listModels: {
                'us-central1': {
                    err: err,
                    data: data
                }
            }
        },
        cryptoKeys: {
            list: {
                'us-central1': {
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

describe('modelEncryption', function () {
    describe('run', function () {
        it('should give unknown result if unable to query Vertex AI models', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Vertex AI models');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no models found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Vertex AI models found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if Vertex AI model has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [models[0]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if Vertex AI model does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [models[1]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        })
    })
});