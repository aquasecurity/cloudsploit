var expect = require('chai').expect;
var securityCenterEdition = require('./securityCenterEdition.js');

const describeVersionConfig = [
    {
        "IsPaidUser": true,
        "ImageScanCapacity": 0,
        "AppWhiteListAuthCount": 0,
        "SasLog": 0,
        "Version": 5,
        "AvdsFlag": 1,
        "HighestVersion": 5,
        "WebLockAuthCount": 0,
        "SlsCapacity": 0,
        "UserDefinedAlarms": 0,
        "AllowPartialBuy": 0,
        "WebLock": 0,
        "IsOverBalance": false,
        "VmCores": 1,
        "HoneypotCapacity": 0,
        "RequestId": "0C1856EE-8FF4-54A0-82AC-F18F63873B38",
        "AssetLevel": 1,
        "InstanceId": "sas-cqtrivxc8k3b",
        "LastInstanceReleaseTime": 1636473600000,
        "CreateTime": 1633794973000,
        "SasScreen": 0,
        "IsSasOpening": false,
        "LogCapacity": 50,
        "Flag": 1,
        "MVAuthCount": 0,
        "GmtCreate": 1633791804000,
        "ReleaseTime": 1636473600000,
        "IsTrialVersion": 0,
        "MVUnusedAuthCount": 0,
        "AppWhiteList": 0
    },
    {
        "IsPaidUser": true,
        "ImageScanCapacity": 0,
        "AppWhiteListAuthCount": 0,
        "SasLog": 0,
        "Version": 6,
        "AvdsFlag": 1,
        "HighestVersion": 6,
        "WebLockAuthCount": 0,
        "SlsCapacity": 0,
        "UserDefinedAlarms": 0,
        "AllowPartialBuy": 0,
        "WebLock": 0,
        "IsOverBalance": false,
        "VmCores": 1,
        "HoneypotCapacity": 0,
        "RequestId": "0C1856EE-8FF4-54A0-82AC-F18F63873B38",
        "AssetLevel": 1,
        "InstanceId": "sas-cqtrivxc8k3b",
        "LastInstanceReleaseTime": 1636473600000,
        "CreateTime": 1633794973000,
        "SasScreen": 0,
        "IsSasOpening": false,
        "LogCapacity": 50,
        "Flag": 1,
        "MVAuthCount": 0,
        "GmtCreate": 1633791804000,
        "ReleaseTime": 1636473600000,
        "IsTrialVersion": 0,
        "MVUnusedAuthCount": 0,
        "AppWhiteList": 0
    }
];

const createCache = (describeVersionConfig, describeVersionConfigErr) => {
    return {
        tds: {
            DescribeVersionConfig: {
                'cn-hangzhou': {
                    data: describeVersionConfig,
                    err: describeVersionConfigErr
                },
            }
        }
    };
};

describe('securityCenterEdition', function () {
    describe('run', function () {
        it('should FAIL if Security Center edition is Basic or Anti-virus', function (done) {
            const cache = createCache(describeVersionConfig[1]);
            securityCenterEdition.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security Center edition is Anti-virus');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if Security Center edition is Advanced or plus', function (done) {
            const cache = createCache(describeVersionConfig[0]);
            securityCenterEdition.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security Center edition is Advanced');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query Security Center version config', function (done) {
            const cache = createCache([], { err: 'Unable to query' });
            securityCenterEdition.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Security Center version config');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
}) 