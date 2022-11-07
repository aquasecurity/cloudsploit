var expect = require('chai').expect;
var plugin = require('./hadoopSecureModeEnabled');

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
            securityConfig: {
                kerberosConfig: {enableKerberos: true}
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
        labels: {}
    },
];

const createCache = (err, data) => {
    return {
        dataproc: {
            list: {
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

describe('hadoopSecureModeEnabled', function () {
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

        it('should give passing result if no clusters are found', function (done) {
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

        it('should give passing result if hadoop secure mode is enabled for the cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Hadoop Secure mode is enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [clusters[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if hadoop secure mode is not enabled for the cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Hadoop Secure mode is not enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [clusters[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})