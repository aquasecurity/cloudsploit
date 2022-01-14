var expect = require('chai').expect;
const versionedBucketsLC = require('./versionedBucketsLC');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    }
];

const getBucketVersioning = [
    { 
        Status: 'Enabled' 
    },
    {}
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
                "NoncurrentVersionTransitions": [
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
                "NoncurrentVersionTransitions": [
                    {
                        "Days": 900,
                        "StorageClass": "STANDARD_IA"
                    }
                ]
            }
        ]
    }
]

const createCache = (buckets, versioning, lifecycle, lifecycleErr) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketVersioning: {
                'us-east-1': {
                    [bucketName]: {
                        data: versioning,
                    },
                },
            },
            getBucketLocation: {
                'us-east-1': {
                    [bucketName]: {
                        data: {
                            LocationConstraint: 'us-east-1'
                        }
                    }
                }
            },
            getBucketLifecycleConfiguration: {
                'us-east-1': {
                    [bucketName]: {
                        data: lifecycle,
                        err: lifecycleErr
                    }
                }
            },
        },
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing s3 buckets'
                    },
                },
            },
            getBucketVersioning: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket versioning'
                    },
                },
            },
        },
    };
};

const createBucketVersioningErrorCache = (buckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketVersioning: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket versioning'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
            getBucketVersioning: {
                'us-east-1': null,
            },
        },
    };
};

describe('versionedBucketsLC', function () {
    describe('run', function () {
        it('should PASS if S3 bucket has versioning and lifecycle configuration enabled for non-current versions', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[0], getBucketLifecycleConfiguration[0]);
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if S3 bucket has versioning disabled', function (done) {
            const cache = createCache([listBuckets[0]], {});
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has versioning enabled but has lifecycle configuration disabled', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[0], { code: 'NoSuchLifecycleConfiguration' });
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has versioning and lifecycle configuration configured but lifecyle policy does not have enabled rules', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[0], getBucketLifecycleConfiguration[2]);
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if S3 bucket has versioning and lifecycle configuration enabled but lifecycle policy includes no rule for non-current objects', function (done) {
            const cache = createCache([listBuckets[0]], getBucketVersioning[0], getBucketLifecycleConfiguration[1]);
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no S3 bucket found', function (done) {
            const cache = createCache([]);
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to get bucket versioning', function (done) {
            const cache = createBucketVersioningErrorCache([listBuckets[0]]);
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            versionedBucketsLC.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});