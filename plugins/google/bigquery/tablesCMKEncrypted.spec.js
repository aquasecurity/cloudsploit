var expect = require('chai').expect;
var plugin = require('./tablesCMKEncrypted');

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
const datasetGet = [
    {
        "kind": "bigquery#dataset",
        "id": "test:test",
        "selfLink": "https://www.googleapis.com/bigquery/v2/projects/project1/datasets/test_ds",
        "datasetReference": { "datasetId": "test", "projectId": "test" },
        "creationTime": "1619622395743",
        "lastModifiedTime": "1619699668544",
        "location": "US",
        "type": "DEFAULT",
        "defaultEncryptionConfiguration": {
            "kmsKeyName": 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2'
        }
    },
    {
        "kind": "bigquery#dataset",
        "id": "test:test",
        "selfLink": "https://www.googleapis.com/bigquery/v2/projects/project-1/datasets/test_ds",
        "datasetReference": { "datasetId": "test", "projectId": "test" },
        "creationTime": "1619622395743",
        "lastModifiedTime": "1619699668544",
        "location": "US",
        "type": "DEFAULT"
    }
];

const createCache = (err, data, keysErr, keysList) => {
    return {
        datasets: {
            get: {
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
                    data: [{ name: 'testproj' }]
                }
            }
        }
    }
};

describe('tablesCMKEncrypted', function () {
    describe('run', function () {
        it('should give unknown result if unable to query BigQuery datasets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query BigQuery datasets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no datasets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No BigQuery datasets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if BigQuery dataset has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasetGet[0]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if BigQuery dataset does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasetGet[1]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        })
    })
});