const expect = require('chai').expect;
var bucketLifecycleConfiguration = require('./bucketLifecycleConfiguration');

const listBuckets = [
    {
        "Name": "s3buckettest",
        "CreationDate": "2021-01-09T02:56:31+00:00"
    },
];

const getBucketLifecycleConfiguration = [
    {
        "Rules": [
            {
                "ID": "akd-36",
                "Filter": {
                    "Prefix": "t-"
                },
                "Status": "Enabled",
                "Transitions": [
                    {
                        "Days": 900,
                        "StorageClass": "STANDARD_IA"
                    }
                ]
            }
        ]
    },
    {
        "Rules": [
            {
                "ID": "akd-36",
                "Filter": {
                    "Prefix": "t-"
                },
                "Status": "Disabled",
                "Transitions": [
                    {
                        "Days": 900,
                        "StorageClass": "STANDARD_IA"
                    }
                ]
            }
        ]
    }
]

const createCache = (listBuckets, getBucketLifecycleConfiguration, listBucketsErr, getBucketLifecycleConfigurationErr) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: listBucketsErr,
                    data: listBuckets
                }
            },
            getBucketLifecycleConfiguration: {
                'us-east-1': {
                    [bucketName]: {
                        err: getBucketLifecycleConfigurationErr,
                        data: getBucketLifecycleConfiguration
                    }
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

describe('bucketLifecycleConfiguration', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has lifecycle configuration enabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketLifecycleConfiguration[0], null, null);
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket does not have lifecycle configuration enabled', function (done) {
            const cache = createCache([listBuckets[0]], {}, null, null);
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has lifecycle configuration disabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketLifecycleConfiguration[1], null);
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 buckets found', function (done) {
            const cache = createCache([]);
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list S3 buckets', function (done) {
            const cache = createCache(null, null, { message: "Unable to list buckets" }, null);
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get bucket lifecycle configuration', function (done) {
            const cache = createCache([listBuckets[0]], null, null, { message: "Unable to get bucket lifecycle configuration"});
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list S3 buckets response not found', function (done) {
            const cache = createNullCache();
            bucketLifecycleConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});