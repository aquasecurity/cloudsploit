var expect = require('chai').expect;
var plugin = require('./dataprocClusterEncryption');

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

const clusters = [
    {
        projectId: 'testproj',
        clusterName: 'cluster-1',
        status: { state: 'RUNNING', stateStartTime: '2022-10-31T19:51:22.817294Z' },
        statusHistory: [
            {
                state: 'CREATING',
                stateStartTime: '2022-10-31T19:49:56.933052Z'
            }
        ],
        config: {
            encryptionConfig: {
                gcePdKmsKeyName: 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2'
            }
        }
    },
    {
        projectId: 'testproj',
        clusterName: 'cluster-2',
        status: { state: 'RUNNING', stateStartTime: '2022-10-31T19:51:22.817294Z' },
        statusHistory: [
          {
            state: 'CREATING',
            stateStartTime: '2022-10-31T19:49:56.933052Z'
          }
        ],
        config: {
            securityConfig: { kerberosConfig: {} },
            endpointConfig: {}
        },
        labels: {}
    },
];

const createCache = (err, data, keysList, keysErr) => {
    return {
        dataproc: {
            list: {
                 'us-central1': {
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

describe('dataprocClusterEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a cluster error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Dataproc clusters');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no dataproc clusters found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Dataproc clusters found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if cluster has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [clusters[0]],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if cluster does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [clusters[1]],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
    })
});
