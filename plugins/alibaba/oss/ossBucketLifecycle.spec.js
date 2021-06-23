var expect = require('chai').expect;
var bucketLifecycle = require('./ossBucketLifecycle.js');

const listBuckets = [
    {
        "name": 'test-bucket',
        "region": 'oss-cn-hangzhou',
        "creationDate": '2021-05-08T10:35:06.000Z',
        "storageClass": 'Standard',
        "StorageClass": 'Standard',
    }
];

const getBucketLifecycle = [
  {
    Rules: [
      {
        Prefix: '',
        Status: 'Enabled',
        Transition: [Object],
        Id: '5ffcaec2-5f02-47cf-acb0-b19cda007e2c'
      },
    ]
  },
  {
    Rules: [
      {
        Status: 'Enabled',
        Transition: [Object],
        Id: '5ffcaec2-5f02-47cf-acb0-b19cda007e2c'
      },
    ]
  },
  {
    Rules: [
      {
        Prefix: 'test',
        Status: 'Enabled',
        Transition: [Object],
        Id: '5ffcaec2-5f02-47cf-acb0-b19cda007e2c'
      },
      {
        Prefix: 'image',
        Status: 'Enabled',
        Transition: [Object],
        Id: '9b8d4949-1199-4a6a-a32f-afc0a300fb85'
      }
    ]
  },
];

const getBucketLifecycleErr = {
  "name": "NoSuchLifecycleError",
  "status": 404,
  "code": "NoSuchLifecycle",
  "requestId": "60D32E229EAA1A33353B3B66",
  "hostId": "akhtar-made-2.oss-us-west-1.aliyuncs.com",
  "params": {
    "method": "GET",
    "bucket": "akhtar-made-2",
    "subres": "lifecycle",
    "successStatuses": [
      200
    ],
    "xmlResponse": true
  }
}

const createCache = (listBuckets, getBucketLifecycle, listBucketsErr, getBucketLifecycleErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        oss: {
            listBuckets: {
                'cn-hangzhou': {
                    data: listBuckets,
                    err: listBucketsErr
                },
            },
            getBucketLifecycle: {
                'cn-hangzhou': {
                    [bucketName]: {
                        data: getBucketLifecycle,
                        err: getBucketLifecycleErr
                    }
                }
            }
        },
    };
};

describe('bucketLifecycle', function () {
    describe('run', function () {
        it('should FAIL if bucket does not have lifecycle policies', function (done) {
            const cache = createCache(listBuckets, undefined, undefined, getBucketLifecycleErr);
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(1);
              expect(results[0].status).to.equal(2);
              expect(results[0].message).to.include('No lifecycle policy exists');
              expect(results[0].region).to.equal('cn-hangzhou');
              done();
            });
        });

        it('should FAIL if bucket lifecycle policy response is malformed', function (done) {
            const cache = createCache(listBuckets, undefined, undefined, getBucketLifecycleErr);
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(1);
              expect(results[0].status).to.equal(2);
              expect(results[0].message).to.include('No lifecycle policy exists');
              expect(results[0].region).to.equal('cn-hangzhou');
              done();
            });
        });

        it('should PASS if bucket has lifecycle policies enabled', function (done) {
            const cache = createCache(listBuckets, getBucketLifecycle[0]);
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(1);
              expect(results[0].status).to.equal(0);
              expect(results[0].message).to.include('Lifecycle policy for bucket is enabled');
              expect(results[0].region).to.equal('cn-hangzhou');
              done();
            });
        });

        it('should PASS if no OSS buckets found', function (done) {
            const cache = createCache([]);
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(1);
              expect(results[0].status).to.equal(0);
              expect(results[0].message).to.include('No OSS buckets found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query for OSS buckets', function (done) {
            const cache = createCache([], null, { err: 'Unable to query for OSS buckets' });
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results[0].message).to.include('Unable to query for OSS buckets');
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query OSS bucket lifecycle policy info', function (done) {
            const cache = createCache(listBuckets, {}, null, 'Unable to query OSS bucket lifecycle policy info');
            bucketLifecycle.run(cache, {}, (err, results) => {
              expect(results[0].message).to.include('Unable to query OSS bucket lifecycle policy info');
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 