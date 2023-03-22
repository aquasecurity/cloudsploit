var expect = require('chai').expect;
var plugin = require('./environmentLabelsAdded');

const createCache = (err, data) => {
    return {
        composer: {
                environments: {
                    'us-central1': {
                        err: err,
                        data: data
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
          environmentSize: 'ENVIRONMENT_SIZE_SMALL',
          recoveryConfig: { scheduledSnapshotsConfig: {} }
        },
        uuid: '1111111111',
        state: 'RUNNING',
        createTime: '2023-03-22T19:48:55.635485Z',
        updateTime: '2023-03-22T20:28:21.177734Z',
        labels: { 'test-label': 'test' }
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

describe('environmentLabelsAdded', function () {
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

        it('should give passing result if no environments are found', function (done) {
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

        it('should give passing result if labels have been added to the environment', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for composer environment');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [environments[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the environmenr', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Composer environment does not have any labels added');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [environments[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})