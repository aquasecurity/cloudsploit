var expect = require('chai').expect;
var plugin = require('./clusterLeastPrivilege');

const createCache = (clusterData) => {
    return {
        clusters: {
            list: {
                'global': {
                    data: clusterData
                }
            }
        }
    }
};

describe('clusterLeastPrivilege', function () {
    describe('run', function () {
        it('should pass no clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No clusters found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail with non-minimal access permission to the cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.equal('No minimal access is allowed on Kubernetes cluster');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'standard-cluster-1',
                        nodeConfig: {
                            serviceAccount: 'default',
                            oauthScopes: [
                                'https://www.googleapis.com/auth/cloud-platform',
                                'https://www.googleapis.com/auth/devstorage.read_only',
                                'https://www.googleapis.com/auth/logging.write',
                                'https://www.googleapis.com/auth/monitoring',
                                'https://www.googleapis.com/auth/servicecontrol',
                                'https://www.googleapis.com/auth/service.management.readonly',
                                'https://www.googleapis.com/auth/trace.append'
                            ]
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass with minimal access permission to the cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Minimal access is allowed on Kubernetes cluster');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'standard-cluster-1',
                        nodeConfig: {
                            serviceAccount: 'default',
                            oauthScopes: [
                                'https://www.googleapis.com/auth/devstorage.read_only',
                                'https://www.googleapis.com/auth/logging.write',
                                'https://www.googleapis.com/auth/monitoring',
                                'https://www.googleapis.com/auth/servicecontrol',
                                'https://www.googleapis.com/auth/service.management.readonly',
                                'https://www.googleapis.com/auth/trace.append'
                            ]
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});