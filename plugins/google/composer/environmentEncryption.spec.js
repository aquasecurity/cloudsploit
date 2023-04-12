var expect = require('chai').expect;
var plugin = require('./environmentEncryption');

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

const environments =  [
    {
        name: 'projects/test-proj/locations/us-central1/environments/test-1',
        config: {
          gkeCluster: 'projects/test-proj/locations/us-central1/clusters/us-central1-test-1-gke',
          dagGcsPrefix: 'gs://us-central1-test-1-bucket/dags',
          softwareConfig: { imageVersion: 'composer-2.1.10-airflow-2.4.3' },
          nodeConfig: {
            network: 'projects/test-proj/global/networks/default',
            subnetwork: 'projects/test-proj/regions/us-central1/subnetworks/default',
            ipAllocationPolicy: {}
          },
          privateEnvironmentConfig: {
            privateClusterConfig: {},
            cloudSqlIpv4CidrBlock: '10.0.0.0/12',
            cloudComposerNetworkIpv4CidrBlock: '172.31.245.0/24'
          },
          encryptionConfig: {
            kmsKeyName: 'projects/test-dev/locations/global/keyRings/test-kr/cryptoKeys/test-key-2'
          },
          environmentSize: 'ENVIRONMENT_SIZE_SMALL',
          recoveryConfig: { scheduledSnapshotsConfig: {} }
        },
        uuid: '1111111111',
        state: 'RUNNING',
        createTime: '2023-03-22T19:48:55.635485Z',
        updateTime: '2023-03-22T20:28:21.177734Z'
      },
      {
        name: 'projects/test-proj/locations/us-central1/environments/test-2',
        config: {
          gkeCluster: 'projects/test-proj/locations/us-central1/clusters/us-central1-test-2-gke',
          dagGcsPrefix: 'gs://us-central1-test-2-bucket/dags',
          softwareConfig: { imageVersion: 'composer-2.1.10-airflow-2.4.3' },
          nodeConfig: {
            network: 'projects/test-proj/global/networks/default',
            subnetwork: 'projects/test-proj/regions/us-central1/subnetworks/default',
            ipAllocationPolicy: {}
          },
          privateEnvironmentConfig: {
            privateClusterConfig: {},
            cloudSqlIpv4CidrBlock: '10.0.0.0/12',
            cloudComposerNetworkIpv4CidrBlock: '172.31.245.0/24'
          },
          environmentSize: 'ENVIRONMENT_SIZE_SMALL',
          recoveryConfig: { scheduledSnapshotsConfig: {} }
        },
        uuid: '1111111111',
        state: 'RUNNING',
        createTime: '2023-03-22T19:48:55.635485Z',
        updateTime: '2023-03-22T20:28:21.177734Z',
      }
]

const createCache = (err, data, keysList, keysErr) => {
    return {
        composer: {
            environments: {
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

describe('environmentEncryption', function () {
    describe('run', function () {
        it('should give unknown result if an environment error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Composer environments');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no composer environments found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Composer environments found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if environmentshas desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [environments[0]],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if environmentsdoes not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('us-central1');
                done()
            };
            const cache = createCache(
                null,
                [environments[1]],
                cryptoKeys,
                null
            );
            plugin.run(cache, {}, callback);
        });
    })
});
