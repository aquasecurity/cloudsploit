var expect = require('chai').expect;
var ossBucketVersioning = require('./ossBucketVersioning.js');

const listBuckets = [
    {
        "name": 'test-bucket',
        "region": 'oss-cn-hangzhou',
        "creationDate": '2021-05-08T10:35:06.000Z',
        "storageClass": 'Standard',
        "StorageClass": 'Standard',
    }
];

const getBucketInfo = [
    {
        "Comment": "",
        "CreationDate": "2021-05-08T18:42:34.000Z",
        "CrossRegionReplication": "Disabled",
        "DataRedundancyType": "LRS",
        "ExtranetEndpoint": "oss-cn-hangzhou.aliyuncs.com",
        "IntranetEndpoint": "oss-cn-hangzhou-internal.aliyuncs.com",
        "Location": "oss-cn-hangzhou",
        "Name": "test-bucket",
        "StorageClass": "Standard",
        "TransferAcceleration": "Disabled",
        "Owner": {
            "DisplayName": "0000111122223333",
            "ID": "0000111122223333"
        },
        "Versioning": "Enabled"
    },
    {
        "Comment": "",
        "CreationDate": "2021-05-08T18:42:34.000Z",
        "CrossRegionReplication": "Disabled",
        "DataRedundancyType": "LRS",
        "ExtranetEndpoint": "oss-cn-hangzhou.aliyuncs.com",
        "IntranetEndpoint": "oss-cn-hangzhou-internal.aliyuncs.com",
        "Location": "oss-cn-hangzhou",
        "Name": "test-bucket",
        "StorageClass": "Standard",
        "TransferAcceleration": "Disabled",
        "Owner": {
            "DisplayName": "0000111122223333",
            "ID": "0000111122223333"
        },
    }
];

const createCache = (listBuckets, getBucketInfo, listBucketsErr, getBucketInfoErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        oss: {
            listBuckets: {
                'cn-hangzhou': {
                    data: listBuckets,
                    err: listBucketsErr
                },
            },
            getBucketInfo: {
                'cn-hangzhou': {
                    [bucketName]: {
                        data: getBucketInfo,
                        err: getBucketInfoErr
                    }
                }
            }
        },
    };
};

describe('ossBucketVersioning', function () {
    describe('run', function () {
        it('should FAIL if bucket versioning is not enabled', function (done) {
            const cache = createCache(listBuckets, getBucketInfo[1]);
            ossBucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bucket does not have versioning enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if bucket versioning is enabled', function (done) {
            const cache = createCache(listBuckets, getBucketInfo[0]);
            ossBucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bucket has versioning enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no OSS buckets found', function (done) {
            const cache = createCache([]);
            ossBucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OSS buckets found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query for OSS buckets', function (done) {
            const cache = createCache([], null, { err: 'Unable to query for OSS buckets' });
            ossBucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for OSS buckets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query OSS bucket info', function (done) {
            const cache = createCache(listBuckets, {}, null, { err: 'Unable to query OSS bucket info' });
            ossBucketVersioning.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OSS bucket info');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 