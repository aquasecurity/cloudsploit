var expect = require('chai').expect;
var s3BucketHasTags = require('./s3BucketHasTags');

const createCache = (bucketData, bucketDataErr, rgData, rgDataErr) => {
    var bucketName = (bucketData && bucketData.length) ? bucketData[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: bucketDataErr,
                    data: bucketData
                }
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: rgDataErr,
                    data: rgData
                }
            }
        }
    }
};


describe('s3BucketHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list the  s3 buckets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for S3 buckets')
                done();
            };

            const cache = createCache( null,{message: 'unable to query for s3 buckets'});
            s3BucketHasTags.run(cache, {}, callback);
        });

        it('should give passing result if no s3 bucket found.', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No S3 buckets found');
                done();
            };
            const cache = createCache([], null);
            s3BucketHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query all resources from group tagging api:');
                done();
            };
            const cache = createCache([{
                "Name": "test-bucket",
                "CreationDate": "November 22, 2021, 15:51:19 (UTC+05:00)",
            }], null, [],{
                message: "Unable to query for Resource group tags"
            });
            s3BucketHasTags.run(cache, {}, callback);
        });

        it('should give passing result if s3 bucket has tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('S3 bucket has tags');
                done();
            };

            const cache = createCache(
                [{
                    "Name": "test-bucket",
                    "CreationDate": "November 22, 2021, 15:51:19 (UTC+05:00)",
                }],null,
                [{
                    "ResourceARN": "arn:aws:s3:::test-bucket",
                    "Tags": [{key:"key1", value:"value"}],
                }],null
            );
            s3BucketHasTags.run(cache, {}, callback);
        });

        it('should give failing result if s3 does not have tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('S3 bucket does not have any tags');
                done();
            };

            const cache = createCache(
                [{
                    "Name": "test-bucket",
                    "CreationDate": "November 22, 2021, 15:51:19 (UTC+05:00)",
                }],null,
                [{
                    "ResourceARN": "arn:aws:s3:::test-bucket",
                    "Tags": [],
                }],null
            );

            s3BucketHasTags.run(cache, {}, callback);
        });

    });
});