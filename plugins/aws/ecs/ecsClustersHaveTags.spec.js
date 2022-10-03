var expect = require('chai').expect;
var ecsClustersHaveTags = require('./ecsClustersHaveTags');

const createCache = (clsuterData, rgData) => {
    return {
        ecs: {
            listClusters: {
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

describe('ecsClustersHaveTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list ECS clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for ECS clusters');
                done();
            };

            const cache = createCache(null, []);
            ecsClustersHaveTags.run(cache, {}, callback);
        });

        it('should give passing result if ecs Clusters not found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS clusters present');
                done();
            };
            const cache = createCache([], null);
            ecsClustersHaveTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query all resources from group tagging api');
                done();
            };

            const cache = createCache(
                ['arn:aws:ecs:us-east-1:101363884315:cluster/test2'],
                null
            );

            ecsClustersHaveTags.run(cache, {}, callback);
        });

        it('should give passing result if ecs Clusters have tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ECS clsuters has tags');
                done();
            };

            const cache = createCache(
                ['arn:aws:ecs:us-east-1:101363884315:cluster/test2'],
                [{
                    "ResourceARN": "arn:aws:ecs:us-east-1:101363884315:cluster/test2",
                    "Tags": [{key:"key1", value:"value"}],
                }]
            );
            ecsClustersHaveTags.run(cache, {}, callback);
        })

        it('should give failing result if ecs cluster does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('ECS clsuters does not have any tags');
                    done();
                };

               const cache = createCache(
                 ['arn:aws:ecs:us-east-1:101363884315:cluster/test2'],
                [{
                    "ResourceARN": "arn:aws:ecs:us-east-1:101363884315:cluster/Test-cluster",
                    "Tags": [],
                }]
            );

            ecsClustersHaveTags.run(cache, {}, callback);
        });

    });
});