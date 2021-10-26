var expect = require('chai').expect;
var securityNotificationsEnabled = require('./securityNotificationsEnabled.js');

const describeNoticeConfig = [
    [
        {
            "Project": "yundun_sas_cloud_native_firewall_Defense",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_cloud_native_firewall",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_aegis_AV_true",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_security_Weekreport",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 2,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_vul_Emergency",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 2,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_webguard_event",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_config_alert",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_ak_leakage",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "sas_suspicious",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "sas_healthcheck",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "sas_vulnerability",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "weeklyreport",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "agent",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_anti_Virus",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_IP_Blocking",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "bruteforcesuccess",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "webshell",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "suspicious",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "patch",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "virusScheduleTask",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "remotelogin",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "health",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 7,
            "AliUid": "5103119194921620"
        }
    ],
    [
        {
            "Project": "yundun_sas_cloud_native_firewall_Defense",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 0,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_cloud_native_firewall",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 0,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_aegis_AV_true",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 7,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_security_Weekreport",
            "CurrentPage": 1,
            "TimeLimit": 1,
            "Route": 2,
            "AliUid": "5103119194921620"
        },
        {
            "Project": "yundun_sas_vul_Emergency",
            "CurrentPage": 1,
            "TimeLimit": 0,
            "Route": 2,
            "AliUid": "5103119194921620"
        }
    ]
];

const createCache = (describeNoticeConfig, describeNoticeConfigErr) => {
    return {
        tds: {
            DescribeNoticeConfig: {
                'cn-hangzhou': {
                    data: describeNoticeConfig,
                    err: describeNoticeConfigErr
                },
            }
        }
    };
};

describe('securityNotificationsEnabled', function () {
    describe('run', function () {
        it('should FAIL if security notifications are not enabled', function (done) {
            const cache = createCache(describeNoticeConfig[1]);
            securityNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security notifications are not enabled');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if security notifications are enabled for all alerts', function (done) {
            const cache = createCache(describeNoticeConfig[0]);
            securityNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security notifications are enabled for all alerts');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should PASS if no TDS notice config found', function (done) {
            const cache = createCache([]);
            securityNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No TDS notice config found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });

        it('should UNKNOWN if Unable to query TDS notice config', function (done) {
            const cache = createCache([], { err: 'Unable to query TDS notice config' });
            securityNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query TDS notice config');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})