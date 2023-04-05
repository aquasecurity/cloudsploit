var expect = require('chai').expect;
var plugin = require('./envDefaultServiceAccount');

const createCache = (data, projectData, error) => {
    return {
            composer: {
                environments: {
                    'us-central1': {
                        data: data,
                        err: error
                    }
            }
        },
        projects : {
            get: {
                'global': {
                    data: projectData
                }
            }
        }
    }
};

const project = {
    kind: "compute#project",
    id: "00000111112222233333",
    defaultServiceAccount: "00000111112222233333-compute@developer.gserviceaccount.com",
}

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
            serviceAccount: '00000111112222233333-compute@developer.gserviceaccount.com',
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
            ipAllocationPolicy: {},
            serviceAccount: '00000111112222233333-compute@dev2.gserviceaccount.com'
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

describe('envDefaultServiceAccount', function () {
    describe('run', function () {

        it('should give unknown if an environment error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Composer environments');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [project],
                { message: 'error'}
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no composer environments', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Composer environments found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [project]
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if any composer environment is using the default service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Composer environment is using default service account');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [environments[0]],
                [project]
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if the composer environment is not using default service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Composer environment is not using default service account');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [environments[1]],
                [project],
                null
            );

            plugin.run(cache, {}, callback);
        })
    })
})