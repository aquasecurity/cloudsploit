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
const tablesGet = [
    {
        "kind": 'bigquery#table',
        "id": 'myproject:ds1.t2',
        "selfLink": 'https://content-bigquery.googleapis.com/bigquery/v2/projects/myproject/datasets/ds1/tables/t2',
        "tableReference": { projectId: 'myproject', datasetId: 'ds1', tableId: 't2' },
        "schema": {},
        "numBytes": '0',
        "numLongTermBytes": '0',
        "numRows": '0',
        "creationTime": '1672707589430',
        "lastModifiedTime": '1672707589540',
        "type": 'TABLE',
        "location": 'us-central1',
        "encryptionConfiguration": {
          "kmsKeyName": 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2'
        },
        "numTotalLogicalBytes": '0',
        "numActiveLogicalBytes": '0',
        "numLongTermLogicalBytes": '0'
    },
    {
        "kind": 'bigquery#table',
        "id": 'myproject:ds1.t1',
        "selfLink": 'https://content-bigquery.googleapis.com/bigquery/v2/projects/myproject/datasets/ds1/tables/t2',
        "tableReference": { projectId: 'myproject', datasetId: 'ds1', tableId: 't1' },
        "schema": {},
        "numBytes": '0',
        "numLongTermBytes": '0',
        "numRows": '0',
        "creationTime": '1672707589430',
        "lastModifiedTime": '1672707589540',
        "type": 'TABLE',
        "location": 'us-central1',
        "numTotalLogicalBytes": '0',
        "numActiveLogicalBytes": '0',
        "numLongTermLogicalBytes": '0'
    }
];

const createCache = (err, data, keysErr, keysList) => {
    return {
        datasets: {
            list: {
                'global': {
                    err: null,
                    data: [
                        {
                            datasetId: 'ds1'
                        }
                    ]
                }
            }
        },
        
        bigqueryTables: {
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
        it('should give unknown result if unable to query BigQuery tables', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query BigQuery tables');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no big query tables found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No BigQuery tables found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []                
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if BigQuery table has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [tablesGet[0]],
                null,
                cryptoKeys
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if BigQuery table does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [tablesGet[1]],
                null,
                cryptoKeys
            );


            plugin.run(cache, {}, callback);
        })
    })
});
