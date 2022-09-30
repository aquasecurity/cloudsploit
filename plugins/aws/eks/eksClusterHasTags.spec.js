var expect = require('chai').expect;
var eksClusterHasTags = require('./eksClusterHasTags');

const createCache = (clsuterData, rgData) => {
    return {
        eks: {
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
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                data: '101363884315'
                }
            }
    }
    }
};

describe('eksClusterHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list eks clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for EKS clusters');
                done()
            };

            const cache = createCache(null, []);
            eksClusterHasTags.run(cache, {}, callback);
        });

        it('should give passing result if EKS Clusters not found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No EKS clusters present');
                done();
            };
            const cache = createCache([], null);
            eksClusterHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query all resources');
                done();
            };

            const cache = createCache(
                ["Test-cluster"],
                null
            );

            eksClusterHasTags.run(cache, {}, callback);
        });

        it('should give passing result if EKS Clusters have tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('EKS cluster has tags');
                done();
            };

            const cache = createCache(
                ["Test-cluster"],
                [{
                    "ResourceARN": "arn:aws:eks:us-east-1:101363884315:cluster/Test-cluster",
                    "Tags": [{key:"key1", value:"value"}],
                }]
            );
            eksClusterHasTags.run(cache, {}, callback);
        });

        it('should give failing result if eks cluster does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('EKS cluster does not have any tags');
                    done();
                };

               const cache = createCache(
                 ['Test-cluster'],
                [{
                    "ResourceARN": "arn:aws:eks:us-east-1:101363884315:cluster/Test-cluster",
                    "Tags": [],
                }]
            );

            eksClusterHasTags.run(cache, {}, callback);
        });

    });
});