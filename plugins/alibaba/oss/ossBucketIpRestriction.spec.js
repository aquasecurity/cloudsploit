var expect = require('chai').expect;
var ossBucketIpRestriction = require('./ossBucketIpRestriction.js');

const listBuckets = [
    {
        "name": 'test-bucket',
        "region": 'oss-cn-hangzhou',
        "creationDate": '2021-05-08T10:35:06.000Z',
        "storageClass": 'Standard',
        "StorageClass": 'Standard',
    }
];

const getBucketPolicy = [
    {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": [
                    "oss:RestoreObject",
                    "oss:ListObjects",
                    "oss:AbortMultipartUpload",
                    "oss:PutObjectAcl",
                    "oss:GetObjectAcl",
                    "oss:ListParts",
                    "oss:DeleteObject",
                    "oss:PutObject",
                    "oss:GetObject",
                    "oss:GetVodPlaylist",
                    "oss:PostVodPlaylist",
                    "oss:PublishRtmpStream",
                    "oss:ListObjectVersions",
                    "oss:GetObjectVersion",
                    "oss:GetObjectVersionAcl",
                    "oss:RestoreObjectVersion"
                ],
                "Principal": [
                    "*"
                ],
                "Resource": [
                    "acs:oss:*:0000111122223333:akhtar-made/*"
                ],
                "Condition": {
                    "IpAddress": {
                        "acs:SourceIp": [ "103.127.36.50" ]
                    }
                }
            }
        ]
    },
    {
        "Version": "1",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "oss:RestoreObject",
                    "oss:ListObjects",
                    "oss:AbortMultipartUpload",
                    "oss:PutObjectAcl",
                    "oss:GetObjectAcl",
                    "oss:ListParts",
                    "oss:DeleteObject",
                    "oss:PutObject",
                    "oss:GetObject",
                    "oss:GetVodPlaylist",
                    "oss:PostVodPlaylist",
                    "oss:PublishRtmpStream",
                    "oss:ListObjectVersions",
                    "oss:GetObjectVersion",
                    "oss:GetObjectVersionAcl",
                    "oss:RestoreObjectVersion"
                ],
                "Principal": [
                    "*"
                ],
                "Resource": [
                    "acs:oss:*:0000111122223333:akhtar-made/*"
                ]
            }
        ]
    },
    {
        "policy": null,
        "status": 404
    }
];

const createCache = (listBuckets, getBucketPolicy, listBucketsErr, getBucketPolicyErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        oss: {
            listBuckets: {
                'cn-hangzhou': {
                    data: listBuckets,
                    err: listBucketsErr
                },
            },
            getBucketPolicy: {
                'cn-hangzhou': {
                    [bucketName]: {
                        data: getBucketPolicy,
                        err: getBucketPolicyErr
                    }
                }
            }
        },
    };
};

describe('ossBucketIpRestriction', function () {
    describe('run', function () {
        it('should PASS if OSS bucket has IP restrictions configured', function (done) {
            const cache = createCache(listBuckets, getBucketPolicy[0]);
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OSS bucket has IP restrictions configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if OSS bucket does not have IP restrictions configured', function (done) {
            const cache = createCache(listBuckets, getBucketPolicy[1]);
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OSS bucket does not have IP restrictions configured');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should FAIL if no OSS bucket policy found', function (done) {
            const cache = createCache(listBuckets, getBucketPolicy[2]);
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No OSS bucket policy found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no OSS buckets found', function (done) {
            const cache = createCache([]);
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OSS buckets found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query for OSS buckets', function (done) {
            const cache = createCache([], null, { err: 'Unable to query for OSS buckets' });
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for OSS buckets');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query OSS bucket policy', function (done) {
            const cache = createCache([listBuckets[0]], {}, null, { err: 'Unable to query OSS bucket policy' });
            ossBucketIpRestriction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OSS bucket policy');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 