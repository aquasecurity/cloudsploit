var assert = require('assert');
var expect = require('chai').expect;
var eks = require('./eksLoggingEnabled');

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

describe('eksLoggingEnabled', function () {
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

        it('should give error result if all EKS logging is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('EKS cluster logging is disabled for')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "logging": {
                      "clusterLogging": [
                        {
                          "types": [
                          ],
                          "enabled": true
                        },
                        {
                          "types": [
                            "api",
                            "audit",
                            "controllerManager",
                            "scheduler",
                            "authenticator"
                          ],
                          "enabled": false
                        }
                      ]
                    }
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give error result if some EKS logging is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('but disabled for')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "logging": {
                      "clusterLogging": [
                        {
                          "types": [
                            "authenticator"
                          ],
                          "enabled": true
                        },
                        {
                          "types": [
                            "api",
                            "audit",
                            "controllerManager",
                            "scheduler"
                          ],
                          "enabled": false
                        }
                      ]
                    }
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give passing result if all EKS logging is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('EKS cluster logging is enabled')
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/mycluster",
                    "logging": {
                      "clusterLogging": [
                        {
                          "types": [
                            "api",
                            "audit",
                            "controllerManager",
                            "scheduler",
                            "authenticator"
                          ],
                          "enabled": true
                        },
                        {
                          "types": [
                          ],
                          "enabled": false
                        }
                      ]
                    }
                  }
                }
            );

            eks.run(cache, {}, callback);
        })
    })
})