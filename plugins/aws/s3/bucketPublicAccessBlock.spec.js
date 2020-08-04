var expect = require('chai').expect;
var bucketPublicAccessBlock = require('./bucketPublicAccessBlock');

const createCache = (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets, s3control) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }]
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            PublicAccessBlockConfiguration: {
                                BlockPublicAcls,
                                IgnorePublicAcls,
                                BlockPublicPolicy,
                                RestrictPublicBuckets,
                            },
                        },
                    },
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '1'
                }
            }
        },
        s3control: {
            getPublicAccessBlock: {
                'us-east-1': {
                    '1': {
                        data: {
                            PublicAccessBlockConfiguration: s3control
                        },
                    },
                },
            }
        }
    };
};

const createCacheNoPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }]
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        err: {
                            code: 'NoSuchPublicAccessBlockConfiguration',
                        },
                    },
                },
            },
        },
    };
};

const createCacheNullListBuckets = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
        },
    };
};

const createCacheNullGetPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: null,
                },
            },
        },
    };
};

const createCacheEmptyListBucket = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createCacheErrorListBucket = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    error: {
                        message: 'bad error',
                    },
                },
            },
        },
    };
};

const createCacheErrorGetPublicAccessBlock = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    mybucket: {
                        error: {
                            message: 'bad error',
                        },
                    },
                },
            },
        },
    };
};

describe('bucketPublicAccessBlock', function () {
    describe('run', function () {
        it('should PASS if public access block is fully configured', function (done) {
            const cache = createCache(
                                        true,
                                        true,
                                        true,
                                        true,
                                        {
                                            BlockPublicAcls: true,
                                            IgnorePublicAcls: true,
                                            BlockPublicPolicy: true,
                                            RestrictPublicBuckets: true,
                                        });

            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no buckets in account', function (done) {
            const cache = createCacheEmptyListBucket();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should do nothing if null listBuckets', function (done) {
            const cache = createCacheNullListBuckets();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error listing buckets', function (done) {
            const cache = createCacheErrorListBucket();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should FAIL if public access block is partially configured', function (done) {
            const cache = createCache(
                                        true,
                                        true,
                                        false,
                                        false,
                                        {
                                            BlockPublicAcls: true,
                                            IgnorePublicAcls: true,
                                            BlockPublicPolicy: false,
                                            RestrictPublicBuckets: false,
                                        });
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if account level covers everything', function (done) {
            const cache = createCache(
                                        true,
                                        true,
                                        false,
                                        false,
                                        {
                                            BlockPublicAcls: true,
                                            IgnorePublicAcls: true,
                                            BlockPublicPolicy: true,
                                            RestrictPublicBuckets: true,
                                        });
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Account level provides blocks for')
                done();
            });
        });

        it('should PASS if bucket level blocks handle missing account blocks', function (done) {
            const cache = createCache(
                                        true,
                                        true,
                                        false,
                                        false,
                                        {
                                            BlockPublicAcls: false,
                                            IgnorePublicAcls: false,
                                            BlockPublicPolicy: true,
                                            RestrictPublicBuckets: true,
                                        });
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Account level provides blocks for')
                done();
            });
        });

        it('should FAIL if account level does not cover missing blocks on bucket', function (done) {
            const cache = createCache(
                                        true,
                                        true,
                                        false,
                                        false,
                                        {
                                            BlockPublicAcls: true,
                                            IgnorePublicAcls: true,
                                            BlockPublicPolicy: false,
                                            RestrictPublicBuckets: true,
                                        });
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Missing public access blocks: BlockPublicPolicy. Account level provides blocks for RestrictPublicBuckets')
                done();
            });
        });

        it('should FAIL if public access block not found', function (done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if public access block not found', function (done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if public access block not found but whitelisted', function (done) {
            const cache = createCacheNoPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {
                s3_public_access_block_allow_pattern: 'mybucket'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should do nothing if null getPublicAccessBlock', function (done) {
            const cache = createCacheNullGetPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error getting public access block', function (done) {
            const cache = createCacheErrorGetPublicAccessBlock();
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
