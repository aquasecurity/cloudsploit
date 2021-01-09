const expect = require('chai').expect;
var bucketAccelerationEnabled = require('./bucketAccelerationEnabled');

const listBuckets = [
    {
        "Name": "s3buckettest",
        "CreationDate": "2021-01-09T02:56:31+00:00"
    },
];

const getBucketAccelerateConfiguration = [
    {
        Status: 'Enabled'
    },
    {
        Status: 'Suspended'
    }
]

const createCache = (listBuckets, getBucketAccelerateConfiguration, listBucketsErr, getBucketAccelerateConfigurationErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: listBucketsErr,
                    data: listBuckets
                }
            },
            getBucketAccelerateConfiguration: {
                'us-east-1': {
                    [bucketName]: {
                        err: getBucketAccelerateConfigurationErr,
                        data: getBucketAccelerateConfiguration
                    }
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null
            }
        }
    };
};

describe('bucketAccelerationEnabled', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has transfer acceleration enabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketAccelerateConfiguration[0], null, null);
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if S3 bucket does not have transfer acceleration enabled', function (done) {
            const cache = createCache([listBuckets[0]], {}, null, null);
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if S3 bucket has transfer acceleration suspended', function (done) {
            const cache = createCache([listBuckets[0]], getBucketAccelerateConfiguration[1], null);
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no S3 buckets found', function (done) {
            const cache = createCache([]);
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createCache(null, null, { message: "Unable to list buckets" }, null);
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get bucket acceleration configuration', function (done) {
            const cache = createCache([listBuckets[0]], null, null, { message: "Unable to get bucket acceleration configuration"});
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                console.log(results);
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if list S3 buckets response not found', function (done) {
            const cache = createNullCache();
            bucketAccelerationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});