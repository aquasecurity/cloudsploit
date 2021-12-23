var assert = require('assert');
var expect = require('chai').expect;
var eks = require('./eksLatestPlatformVersion');

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
                    'das': {
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


describe('eksLatestPlatformVersion', function () {
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

        it('should give passing result if EKS cluster running platform is deprecated', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('EKS cluster using deprecated EKS version')
                done()
            };

            const cache = createCache(
                ['das'],
                {
                  "cluster": {
                    "name": "das",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/das",
                    "version": "1.16",
                    "platformVersion": "eks.9",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give passing result if EKS cluster is latest', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('EKS cluster is running latest EKS platform version')
                done()
            };

            const cache = createCache(
                ['das'],
                {
                  "cluster": {
                    "name": "das",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/das",
                    "version": "1.21",
                    "platformVersion": "eks.3",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })

        it('should give error result if EKS cluster is not the latest', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('EKS cluster is not running latest EKS platform version')
                done()
            };

            const cache = createCache(
                ['das'],
                {
                  "cluster": {
                    "name": "das",
                    "arn": "arn:aws:eks:us-east-1:012345678911:cluster/das",
                    "version": "1.21",
                    "platformVersion": "eks.2",
                  }
                }
            );

            eks.run(cache, {}, callback);
        })
    })
})