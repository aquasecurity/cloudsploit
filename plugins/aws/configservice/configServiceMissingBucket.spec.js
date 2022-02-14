var expect = require('chai').expect;
const configServiceMissingBucket = require('./configServiceMissingBucket');

const describeDeliveryChannels = [
    {
        "name": "default",
        "s3BucketName": "config-bucket-000011112222",
        "s3KeyPrefix": "mine"
    },
    {
        "name": "default",
        "s3BucketName": "amazon-connect-e39f272cf1f0",
        "s3KeyPrefix": "mine"
    }
];

const createCache = (records, headBucket, recordsErr, headBucketErr) => {
    var name = (records && records.length) ? records[0].s3BucketName : null;
    return {
        configservice: {
            describeDeliveryChannels: {
                'us-east-1': {
                    err: recordsErr,
                    data: records
                },
            },
        },
        s3: {
            headBucket: {
                'us-east-1': {
                    [name]: {
                        data: headBucket,
                        err: headBucketErr
                    }
                }
            }

        },
    }
}

describe('configServiceMissingBucket', function () {
    describe('run', function () {
        it('should PASS if Config Service is not referencing any deleted bucket', function (done) {
            const cache = createCache([describeDeliveryChannels[1]], null);
            configServiceMissingBucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Config Service is not referencing any deleted bucket')
                done();
            });
        });

        it('should FAIL if Config Service is referencing these deleted buckets', function (done) {
            const cache = createCache([describeDeliveryChannels[0]],null, null, { message: "A client error (404) occurred when calling the HeadBucket operation: Not Found.", code: 'NotFound' });
            configServiceMissingBucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Config Service is referencing these deleted buckets')
                done();
            });
        });

        it('should PASS if no Config delivery channels found', function (done) {
            const cache = createCache([]);
            configServiceMissingBucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Config delivery channels found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query S3 bucket', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to query S3 bucket" });
            configServiceMissingBucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query Config delivery channels', function (done) {
            const cache = createCache(null, null, { message: "Unable to query Config delivery channels" });
            configServiceMissingBucket.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})