var assert = require('assert');
var expect = require('chai').expect;
var ecs = require('./ecsEncryptionEnabled');

const createCache = (listData, descData) => {
    return {
        ecs: {
            listClusters: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeCluster: {
                'us-east-1': {
                    'arn:aws:ecs:us-east-1:101363889637:cluster/khurram-ecs': {
                        err: null,
                        data: descData
                    }
                }
            }
        },
    }
};

describe('ECSEncryptionEnabled', function () {
    describe('run', function () {
        it('should give passing result if no ECS clusters present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No ECS clusters present')
                done()
            };

            const cache = createCache([], {});

            ecs.run(cache, {}, callback);
        })
        it('should give Unknown result if unable to query ecs cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for ECS clusters')
                done()
            };

            const cache = createCache(
                null,
                {
                  "clusters": [{
                    "name": "khurram-ecs",
                    "arn": "arn:aws:ecs:us-east-1:101363889637:cluster/khurram-ecs",
                    "settings": [{"name": "containerInsights", value: "enabled"}]
                  }]}
                
            );
            ecs.run(cache, {}, callback);
        })

        it('should give unknown result if unable to describe the cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to describe ECS cluster');
                done();
        };

            const cache = createCache(
                ['arn:aws:ecs:us-east-1:101363889637:cluster/khurram-ecs'],
                null
                
            );
            ecs.run(cache, {}, callback);
        });

        it('should give passing result if ecs cluster has encryption enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ECS cluster has ecryption enabled');
                done();
            };

          const cache = createCache(
                ['arn:aws:ecs:us-east-1:101363889637:cluster/khurram-ecs'],
                {
                  "clusters": [{
                    "name": "khurram-ecs",
                    "arn": "arn:aws:ecs:us-east-1:012345678911:cluster/khurram-ecs",
                    "configuration": {
                        "executeCommandConfiguration": 
                        { "KmsKeyId": '70c41cfe-e9fe-4007-b7bb-a0f0b859c5e6'}
                      },
                  }]}
                
            );
            ecs.run(cache, {}, callback);
        });

        it('should give Fail result if ecs cluster does not have encryption enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ECS cluster does not have ecryption enabled');
                done();
            };

          const cache = createCache(
                ['arn:aws:ecs:us-east-1:101363889637:cluster/khurram-ecs'],
                {
                  "clusters": [{
                    "name": "khurram-ecs",
                    "arn": "arn:aws:ecs:us-east-1:012345678911:cluster/khurram-ecs",
                    "configuration": {
                        "executeCommandConfiguration": 
                        { }
                      },
                  }]}
                
            );
            ecs.run(cache, {}, callback);
        });

        
    });
})