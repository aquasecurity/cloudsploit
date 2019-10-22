var assert = require('assert');
var expect = require('chai').expect;
var eks = require('./eksKubernetesVersion');

const createCache = (listData, descData) => {
    return {
        eks: {
            listClusters: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeCluster: {
                'us-east-1': {
                    'mycluster': {
                        err: null,
                        data: descData
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    }
};

describe('eksKubernetesVersion', function () {
    describe('run', function () {
        it('should give passing result if no EKS clusters present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No EKS clusters present')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            eks.run(cache, {}, callback);
        })

        it('should give error result if EKS cluster is deprecated', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('which was deprecated')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "version": "1.10",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give warning result if EKS cluster is outdated', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('which is currently outdated')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "version": "1.12",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give passing result if EKS cluster is current', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('current version of Kubernetes')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "version": "1.13",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })
    })
})