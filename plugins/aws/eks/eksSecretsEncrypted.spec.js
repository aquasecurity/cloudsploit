var expect = require('chai').expect;
var eks = require('./eksSecretsEncrypted');

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
        }
    }
};

describe('eksSecretsEncrypted', function () {
    describe('run', function () {
        it('should give passing result if no EKS clusters present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            eks.run(cache, {}, callback);
        });

        it('should give error result if envelope encryption of Kubernetes secrets is not enabled for EKS cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/mycluster",
                    },
                    "encryptionConfig": [
                    ]
                }
            );

            eks.run(cache, {}, callback);
        });

        it('should give passing result if envelope encryption of Kubernetes secrets is enabled for EKS cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                {
                  "cluster": {
                    "name": "mycluster",
                    "arn": "arn:aws:eks:us-east-1:111122223333:cluster/mycluster",
                    "encryptionConfig": [
                        {
                            "resources": [
                                "secrets"
                            ],
                            "provider": {
                                "keyArn": "arn:aws:kms:us-east-1:560213429563:key/e29030ff-0833-432d-83fc-e8072e12be69"
                            }
                        }
                    ]
                  }
                }
            );

            eks.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for EKS clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            };

            const cache = createCache(
                null
            );

            eks.run(cache, {}, callback);
        });

        it('should give unknown result if unable to describe EKS cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                done()
            };

            const cache = createCache(
                ['mycluster'],
                null
            );

            eks.run(cache, {}, callback);
        });
    })
})