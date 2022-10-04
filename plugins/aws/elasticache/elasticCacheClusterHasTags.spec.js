var expect = require('chai').expect;
var elastiCacheClusterHasTags = require('./elasticCacheClusterHasTags');

const createCache = (clsuterData, rgData) => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: null,
                    data: clsuterData
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    }
};

describe('elastiCacheClusterHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list elastiCache clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for ElastiCache clusters');
                done()
            };

            const cache = createCache(null, []);
            elastiCacheClusterHasTags.run(cache, {}, callback);
        });

        it('should give passing result if elastiCache Clusters not found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ElastiCache clusters found');
                done();
            };
            const cache = createCache([], null);
            elastiCacheClusterHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query all resources from group tagging api');
                done();
            };

            const cache = createCache(
                [{
                    ARN: 'arn:aws:elasticache:us-east-1:201363884315:cluster:test-001'
                }],
                null
            );

            elastiCacheClusterHasTags.run(cache, {}, callback);
        });

        it('should give passing result if elastiCache Clusters have tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ElastiCache cluster has tags');
                done();
            };

            const cache = createCache(
                [{
                    ARN: 'arn:aws:elasticache:us-east-1:201363884315:cluster:test-001'
                }],
                [{
                    'ResourceARN': 'arn:aws:elasticache:us-east-1:201363884315:cluster:test-001',
                    'Tags': [{key:'key1', value:'value'}],
                }]
            );
            elastiCacheClusterHasTags.run(cache, {}, callback);
        });

        it('should give failing result if elastiCache cluster does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('ElastiCache cluster does not have any tags');
                    done();
                };

               const cache = createCache(
                 [{
                    ARN: 'arn:aws:elasticache:us-east-1:201363884315:cluster:test-001'
                }],
                [{
                    'ResourceARN': 'arn:aws:elasticache:us-east-1:201363884315:cluster:test-001',
                    'Tags': [],
                }]
            );

            elastiCacheClusterHasTags.run(cache, {}, callback);
        });

    });
});