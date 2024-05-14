const expect = require('chai').expect;
const documentDBHasTags = require('./docDbHasTags');

const createCache = (clusters, tags) => {
    return {
        docdb: {
            describeDBClusters: {
                'us-east-1': {
                    err: null,
                    data: clusters
                }
            },
            listTagsForResource: {
                'us-east-1': {
                    'arn:aws:rds:us-east-1:000011112222:cluster:test-cluster': {
                        err: null,
                        data: tags
                    }
                }
            }
        }
    };
};

describe('DocumentDB Has Tags', function () {
    describe('run', function () {
        it('should return unknown result if unable to list DocumentDB clusters', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list DocumentDB clusters');
                done();
            };

            const cache = createCache(null, null);

            documentDBHasTags.run(cache, {}, callback);
        });

        it('should return unknown result if unable to get tags information for DocumentDB cluster', function (done) {
            const clusters = [
                {
                    DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:test-cluster'
                }
            ];

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get tags information for doc db cluster');
                done();
            };

            const cache = createCache(clusters, null);

            documentDBHasTags.run(cache, {}, callback);
        });

        it('should return passing result if DocumentDB cluster has tags associated', function (done) {
            const clusters = [
                {
                    DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:test-cluster'
                }
            ];

            const tags = {
                TagList: [
                    { Key: 'abc', Value: 'value' }                ]
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('DocumentDB cluster has tags associated');
                done();
            };

            const cache = createCache(clusters, tags);

            documentDBHasTags.run(cache, {}, callback);
        });

        it('should return failing result if DocumentDB cluster does not have tags associated', function (done) {
            const clusters = [
                {
                    DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:test-cluster'
                }
            ];

            const tags = {
                TagList: []
            };

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('DocumentDB cluster does not have tags associated');
                done();
            };

            const cache = createCache(clusters, tags);

            documentDBHasTags.run(cache, {}, callback);
        });

        it('should return passing result if no DocumentDB clusters found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No DocumentDB clusters found');
                done();
            };

            const cache = createCache([], null);

            documentDBHasTags.run(cache, {}, callback);
        });
    });
});
