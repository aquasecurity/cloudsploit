var expect = require('chai').expect;
var bucketRequestPayment = require('./bucketPayByRequester.js');

const listBuckets = [
    {
        "name": 'test-bucket',
        "region": 'oss-cn-hangzhou',
        "creationDate": '2021-05-08T10:35:06.000Z',
        "storageClass": 'Standard',
        "StorageClass": 'Standard',
    }
];

const getBucketRequestPayment = [
    {
        "payer": "requester"
    },
    {
        "payer": "bucketowner"
    },   
    {}   
];

const createCache = (listBuckets, getBucketRequestPayment, listBucketsErr, getBucketRequestPaymentErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        oss: {
            listBuckets: {
                'cn-hangzhou': {
                    data: listBuckets,
                    err: listBucketsErr
                },
            },
            getBucketRequestPayment: {
                'cn-hangzhou': {
                    [bucketName]: {
                        data: getBucketRequestPayment,
                        err: getBucketRequestPaymentErr
                    }
                }
            }
        },
    };
};

describe('bucketRequestPayment', function () {
    describe('run', function () {
        it('should FAIL if bucket does not have pay per requester enabled', function (done) {
            const cache = createCache(listBuckets, getBucketRequestPayment[1]);
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not have pay-by-requester feature enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should FAIL if payer property is not returned', function (done) {
            const cache = createCache(listBuckets, getBucketRequestPayment[2]);
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not have pay-by-requester feature enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if bucket has pay per requester enabled', function (done) {
            const cache = createCache(listBuckets, getBucketRequestPayment[0]);
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket has pay-by-requester feature enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no OSS buckets found', function (done) {
            const cache = createCache([]);
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OSS buckets found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query for OSS buckets', function (done) {
            const cache = createCache([], null, { err: 'Unable to query for OSS buckets' });
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for OSS buckets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query OSS bucket info', function (done) {
            const cache = createCache(listBuckets, {}, null, { err: 'Unable to query OSS bucket info' });
            bucketRequestPayment.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OSS bucket info');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 