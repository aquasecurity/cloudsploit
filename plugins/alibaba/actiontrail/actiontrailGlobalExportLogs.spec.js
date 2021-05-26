var expect = require('chai').expect;
var actiontrailGlobalExportLogs = require('./actiontrailGlobalExportLogs')

const describeTrails = [
    {
        Status: 'Enable',
        HomeRegion: 'us-west-1',
        StartLoggingTime: '2021-05-25T15:20:06Z',
        CreateTime: '2021-05-25T15:20:05Z',
        SlsWriteRoleArn: 'acs:ram::0000111122223333:role/aliyunserviceroleforactiontrail',
        OssBucketLocation: '',
        TrailRegion: 'All',
        Name: 'akhtar-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/akhtar-proj',
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
        Name: 'akhtar-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/akhtar-proj',
        EventRW: 'All',
        OssKeyPrefix: '',
        UpdateTime: '2021-05-25T15:20:06Z',
        Region: 'us-west-1',
        OssBucketName: '',
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
        Name: 'akhtar-at',
        IsOrganizationTrail: false,
        SlsProjectArn: 'acs:log:us-west-1:0000111122223333:project/akhtar-proj',
        EventRW: 'Write',
        OssKeyPrefix: '',
        UpdateTime: '2021-05-25T15:20:06Z',
        Region: 'us-west-1',
        OssBucketName: '',
        OssWriteRoleArn: '',
        IsShadowTrail: 0
    }
];


const createCache = (describeTrails, describeTrailsErr) => {
    return {
        actiontrail: {
            DescribeTrails: {
                'cn-hangzhou': {
                    data: describeTrails,
                    err: describeTrailsErr
                }
            }
        }
    }
}

describe('actiontrailGlobalExportLogs', function () {
    describe('run', function () {
        it('should FAIL if ActionTrail does not have global trail to log all events', function (done) {
            const cache = createCache([describeTrails[2]]);
            actiontrailGlobalExportLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ActionTrail does not have global trail to log all events');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should FAIL if ActionTrail has global trail to log all events but does not export logs to OSS bucket', function (done) {
            const cache = createCache([describeTrails[1]]);
            actiontrailGlobalExportLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('ActionTrail has global trail to log all events but does not export logs to OSS bucket');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should PASS if ActionTrail has global trails to log all events', function (done) {
            const cache = createCache([describeTrails[0]]);
            actiontrailGlobalExportLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('ActionTrail has a global trail to log all events');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should UNKNOWN if unable to query ActionTrail trails', function (done) {
            const cache = createCache([], { err: 'Unable to query ActionTrail trails' });
            actiontrailGlobalExportLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query ActionTrail trails');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
