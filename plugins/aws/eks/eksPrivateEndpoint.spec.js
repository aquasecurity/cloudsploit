var assert = require('assert');
var expect = require('chai').expect;
var eks = require('./eksPrivateEndpoint');

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

describe('eksPrivateEndpoint', function () {
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

        it('should give error result if all EKS private endpoint is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('EKS cluster does not have private endpoint')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "resourcesVpcConfig": {
                      "endpointPrivateAccess": false
                    }
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give passing result if all EKS private endpoint is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('EKS cluster has private endpoint')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "resourcesVpcConfig": {
                      "endpointPrivateAccess": true
                    }
                  }
                }
            );

            eks.run(cache, {}, callback);
        })
    })
})