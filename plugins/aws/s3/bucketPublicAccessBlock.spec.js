var expect = require('chai').expect;
var bucketPublicAccessBlock = require('./bucketPublicAccessBlock');

const listBuckets = [
    {
        "Name": "s3-bucket-1",
        "CreationDate": "2020-09-17T18:17:50.000Z"
      },
      {
        "Name": "s3-bucket-2",
        "CreationDate": "2020-08-20T17:42:52.000Z"
      },
      {
        "Name": "s3-bucket-3",
        "CreationDate": "2020-09-25T14:33:28.000Z"
      },
      {
        "Name": "s3-bucket-4",
        "CreationDate": "2020-09-17T18:14:06.000Z"
      }
];

const getPublicAccessBlock = [
    {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true
        }
    },
    {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          IgnorePublicAcls: false,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: false
        }
    }
];

const getCallerIdentity = [
    '112233445566'
];

const createCache = (listBuckets, getPublicAccessBlock, accountId) => {
    var bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    [bucketName]: {
                        data: getPublicAccessBlock
                    },
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: accountId
                }
            }
        },
        s3control: {
            getPublicAccessBlock: {
                'us-east-1': {
                    [accountId]: {
                        data: getPublicAccessBlock
                    }
                }
            }
        }
    };
};

const createCacheNoPublicAccessBlock = (listBuckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
                        err: {
                            code: 'NoSuchPublicAccessBlockConfiguration',
                        },
                    },
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
                    err: {
                        message: 'error while listing S3 bucket',
                    },
                },
            },
        },
    };
};

const createCacheNullListBuckets = () => {
    return {
        s3: {
            listBuckets: null
        },
    };
};

const createCacheErrorGetPublicAccessBlock = (listBuckets) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: listBuckets
                },
            },
            getPublicAccessBlock: {
                'us-east-1': {
                    [listBuckets[0].Name]: {
                        err: {
                            message: 'error describing get public access block',
                        },
                    },
                },
            },
        },
    };
};

describe('bucketPublicAccessBlock', function () {
    describe('run', function () {
        it('should PASS if AWS account has public access block fully enabled', function (done) {
            const cache = createCache([listBuckets[0]], getPublicAccessBlock[0], getCallerIdentity[0]);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if S3 bucket has public access block fully enabled', function (done) {
            const cache = createCache([listBuckets[0]], getPublicAccessBlock[0], getCallerIdentity[0]);
            const settings = { check_global_block: 'false' };
            bucketPublicAccessBlock.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no buckets in account', function (done) {
            const cache = createCache([]);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should do nothing if null listBuckets', function (done) {
            bucketPublicAccessBlock.run({ s3: { listBuckets: null }}, {}, (err, results) => {
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

        it('should FAIL if AWS account is missing public access block', function (done) {
            const cache = createCache([listBuckets[0]], getPublicAccessBlock[1], getCallerIdentity[0]);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if S3 bucket is missing public access block', function (done) {
            const cache = createCache([listBuckets[0]], getPublicAccessBlock[1], getCallerIdentity[0]);
            bucketPublicAccessBlock.run(cache, { check_global_block: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if public access block not found', function (done) {
            const cache = createCacheNoPublicAccessBlock([listBuckets[0]]);
            bucketPublicAccessBlock.run(cache, { check_global_block: 'false' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if public access block not found but whitelisted', function (done) {
            const cache = createCacheNoPublicAccessBlock([listBuckets[0]]);
            bucketPublicAccessBlock.run(cache, {
                s3_public_access_block_allow_pattern: listBuckets[0].Name,
                check_global_block: 'false'
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error getting public access block', function (done) {
            const cache = createCacheErrorGetPublicAccessBlock(listBuckets);
            bucketPublicAccessBlock.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
