var expect = require('chai').expect;
var actiontrailBucketPrivate = require('./actiontrailBucketPrivate')

const describeTrails = [
    {
        Status: 'Enable',
        HomeRegion: 'us-west-1',
        StartLoggingTime: '2021-05-25T15:20:06Z',
        CreateTime: '2021-05-25T15:20:05Z',
        SlsWriteRoleArn: 'acs:ram::0000111122223333:role/aliyunserviceroleforactiontrail',
        OssBucketLocation: '',
        TrailRegion: 'All',
        Name: 'aqua-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/aqua-proj',
        EventRW: 'All',
        OssKeyPrefix: '',
        UpdateTime: '2021-05-25T15:20:06Z',
        Region: 'us-west-1',
        OssBucketName: 'trail-bucket',
        OssWriteRoleArn: '',
        IsShadowTrail: 0
    },
    {
        Status: 'Enable',
        HomeRegion: 'us-west-1',
        StartLoggingTime: '2021-05-25T15:20:06Z',
        CreateTime: '2021-05-25T15:20:05Z',
        SlsWriteRoleArn: 'acs:ram::0000111122223333:role/aliyunserviceroleforactiontrail',
        OssBucketLocation: '',
        TrailRegion: 'All',
        Name: 'aqua-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/aqua-proj',
        EventRW: 'All',
        OssKeyPrefix: '',
        UpdateTime: '2021-05-25T15:20:06Z',
        Region: 'us-west-1',
        OssBucketName: 'trail-bucket',
        OssWriteRoleArn: '',
        IsShadowTrail: 0
    },
    {
        Status: 'Enable',
        HomeRegion: 'us-west-1',
        StartLoggingTime: '2021-05-25T15:20:06Z',
        CreateTime: '2021-05-25T15:20:05Z',
        SlsWriteRoleArn: 'acs:ram::0000111122223333:role/aliyunserviceroleforactiontrail',
        OssBucketLocation: '',
        TrailRegion: 'us-west-1',
        Name: 'aqua-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/aqua-proj',
        EventRW: 'Write',
        OssKeyPrefix: '',
        UpdateTime: '2021-05-25T15:20:06Z',
        Region: 'us-west-1',
        OssBucketName: '',
        OssWriteRoleArn: '',
        IsShadowTrail: 0
    }
];

const listBuckets = [
    {
        "name": 'trail-bucket',
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
        "Name": "trail-bucket",
        "StorageClass": "Standard",
        "TransferAcceleration": "Disabled",
        "Owner": {
            "DisplayName": "0000111122223333",
            "ID": "0000111122223333"
        },
        "AccessControlList": {
            "Grant": "private"
        },
        "ServerSideEncryptionRule": {
            "SSEAlgorithm": "None"
        },
        "BucketPolicy": {
            "LogBucket": "",
            "LogPrefix": ""
        }
    },
    {
        "Comment": "",
        "CreationDate": "2021-05-08T18:42:34.000Z",
        "CrossRegionReplication": "Disabled",
        "DataRedundancyType": "LRS",
        "ExtranetEndpoint": "oss-cn-hangzhou.aliyuncs.com",
        "IntranetEndpoint": "oss-cn-hangzhou-internal.aliyuncs.com",
        "Location": "oss-cn-hangzhou",
        "Name": "trail-bucket",
        "StorageClass": "Standard",
        "TransferAcceleration": "Disabled",
        "Owner": {
            "DisplayName": "0000111122223333",
            "ID": "0000111122223333"
        },
        "AccessControlList": {
            "Grant": "public-read-write"
        },
        "ServerSideEncryptionRule": {
            "SSEAlgorithm": "None"
        },
        "BucketPolicy": {
            "LogBucket": "",
            "LogPrefix": ""
        }
    }
];


const createCache = (listBuckets, listBucketsErr, describeTrails, describeTrailsErr, getBucketInfo, getBucketInfoErr) => {
    let bucketName = (listBuckets && listBuckets.length) ? listBuckets[0].name : null;
    return {
        actiontrail: {
            DescribeTrails: {
                'cn-hangzhou': {
                    data: describeTrails,
                    err: describeTrailsErr
                }
            }
        },
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
        }
    }
}

describe('actiontrailBucketPrivate', function () {
    describe('run', function () {
        it('should FAIL if ActionTrail trail Bucket ACL allows public access', function (done) {
            const cache = createCache(listBuckets, null, [describeTrails[1]], null, getBucketInfo[1]);
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ActionTrail trail Bucket ACL allows public-read-write access');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if ActionTrail trail Bucket ACL allows private access', function (done) {
            const cache = createCache(listBuckets, null, [describeTrails[0]], null, getBucketInfo[0]);
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ActionTrail trail Bucket ACL allows private access');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no ActionTrail trail found', function (done) {
            const cache = createCache(listBuckets, null, []);
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ActionTrail trail found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no ActionTrail trail with OSS bucket destination found', function (done) {
            const cache = createCache(listBuckets, null, [describeTrails[2]], null);
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ActionTrail trail with OSS bucket destination found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query ActionTrail trails', function (done) {
            const cache = createCache(listBuckets, null, [], { err: 'Unable to query ActionTrail trails' });
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ActionTrail trails');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if unable to query OSS bucket info', function (done) {
            const cache = createCache(listBuckets, null, describeTrails, null, null, { err: 'Unable to query OSS bucket info' });
            actiontrailBucketPrivate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OSS bucket info');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
