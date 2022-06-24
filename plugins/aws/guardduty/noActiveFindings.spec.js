var expect = require('chai').expect;
const noActiveFindings = require('./noActiveFindings');

var failDate = new Date();
failDate.setMonth(failDate.getMonth() - 1);

const listDetectors = [
    "febe94ba60bad6400e7ea861564c3e23"
];

const getDetector = [
    {
        "CreatedAt": "2021-11-16T15:54:17.530Z",
        "FindingPublishingFrequency": "SIX_HOURS",
        "ServiceRole": "arn:aws:iam::000011112222:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        "Status": "DISABLED",
        "UpdatedAt": "2021-12-01T14:13:59.029Z",
        "DataSources": {
          "CloudTrail": {
            "Status": "ENABLED"
          },
          "DNSLogs": {
            "Status": "ENABLED"
          },
          "FlowLogs": {
            "Status": "ENABLED"
          },
          "S3Logs": {
            "Status": "ENABLED"
          }
        },
        "Tags": {}
    }
];

const listFindings = {
    FindingIds: [
    "60bebb31f802c270ce9157b51e3d5e5a",
    "6ebebb2c1a90f5d5a307371067738422",
    "78bebb2c1a926382babbd5f9726c012f",
    "c2bea3df06236ff0cc563bed3bb184b0"
    ]
};

const getFindings = [
    {
        "Findings": [
            {
                "AccountId": "000011112222",
                "Arn": "arn:aws:guardduty:us-east-1:000011112222:detector/febe94ba60bad6400e7ea861564c3e23/finding/c2bea3df06236ff0cc563bed3bb184b0",
                "CreatedAt": failDate,
                "Description": "AWS CloudTrail trail codepipeline-source-trail was disabled by sadeed calling PutEventSelectors under unusual circumstances. This can be attackers attempt to cover their tracks by eliminating any trace of activity performed while they accessed your account.",
                "Id": "c2bea3df06236ff0cc563bed3bb184b0",
                "Partition": "aws",
                "Region": "us-east-1",
                "Resource": {
                "AccessKeyDetails": {
                    "AccessKeyId": "ASIARPGOCGXS5IZZUZNG",
                    "PrincipalId": "AIDARPGOCGXSQEYQAT545",
                    "UserName": "sadeed",
                    "UserType": "IAMUser"
                },
                "ResourceType": "AccessKey"
                },
                "SchemaVersion": "2.0",
                "Service": {
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                    "Api": "PutEventSelectors",
                    "CallerType": "Remote IP",
                    "RemoteIpDetails": {
                        "City": {
                        "CityName": "Lahore"
                        },
                        "Country": {
                        "CountryName": "Pakistan"
                        },
                        "GeoLocation": {
                        "Lat": 31.5822,
                        "Lon": 74.3292
                        },
                        "IpAddressV4": "72.255.36.31",
                        "Organization": {
                        "Asn": "9541",
                        "AsnOrg": "Cyber Internet Services Pvt Ltd.",
                        "Isp": "Cybernet",
                        "Org": "Cybernet"
                        }
                    },
                    "ServiceName": "cloudtrail.amazonaws.com"
                    }
                },
                "Archived": false,
                "Count": 2,
                "DetectorId": "febe94ba60bad6400e7ea861564c3e23",
                "EventFirstSeen": "2021-11-22T12:45:25.000Z",
                "EventLastSeen": "2021-11-22T13:09:26.000Z",
                "ResourceRole": "TARGET",
                "ServiceName": "guardduty"
                },
                "Severity": 2,
                "Title": "AWS CloudTrail trail codepipeline-source-trail was disabled.",
                "Type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
                "UpdatedAt": "2021-11-22T13:25:38.883Z"
            }
        ]
    },
    {
        "Findings": [
            {
                "AccountId": "000011112222",
                "Arn": "arn:aws:guardduty:us-east-1:000011112222:detector/febe94ba60bad6400e7ea861564c3e23/finding/60bebb31f802c270ce9157b51e3d5e5a",
                "CreatedAt": new Date(),
                "Description": "API ListFindings was invoked using root credentials from IP address 103.127.36.50.",
                "Id": "60bebb31f802c270ce9157b51e3d5e5a",
                "Partition": "aws",
                "Region": "us-east-1",
                "Resource": {
                "AccessKeyDetails": {
                    "AccessKeyId": "ASIARPGOCGXSYK2EKS4B",
                    "PrincipalId": "000011112222",
                    "UserName": "aws-viteace",
                    "UserType": "Root"
                },
                "ResourceType": "AccessKey"
                },
                "SchemaVersion": "2.0",
                "Service": {
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "AwsApiCallAction": {
                    "Api": "ListFindings",
                    "CallerType": "Remote IP",
                    "RemoteIpDetails": {
                        "City": {
                        "CityName": "Lahore"
                        },
                        "Country": {
                        "CountryName": "Pakistan"
                        },
                        "GeoLocation": {
                        "Lat": 31.5822,
                        "Lon": 74.3292
                        },
                        "IpAddressV4": "103.127.36.50",
                        "Organization": {
                        "Asn": "136030",
                        "AsnOrg": "Redtone Telecommunications Pakistan Private Limited",
                        "Isp": "Redtone Telecommunications Pakistan Private Limite",
                        "Org": "Redtone Telecommunications Pakistan Private Limite"
                        }
                    },
                    "ServiceName": "guardduty.amazonaws.com"
                    }
                },
                "Archived": false,
                "Count": 16,
                "DetectorId": "febe94ba60bad6400e7ea861564c3e23",
                "EventFirstSeen": "2021-12-01T14:19:55.000Z",
                "EventLastSeen": "2021-12-01T14:25:28.000Z",
                "ResourceRole": "TARGET",
                "ServiceName": "guardduty"
                },
                "Severity": 2,
                "Title": "API ListFindings was invoked using root credentials.",
                "Type": "Policy:IAMUser/RootCredentialUsage",
                "UpdatedAt": "2021-12-01T14:31:01.095Z"
            },
        ]
    }
];

const createCache = (listDetectors, getDetector, listFindings, getFindings, listDetectorsErr, getDetectorErr) => {
    let detectorId = (listDetectors.length) ? listDetectors[0] : null;
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    data: listDetectors,
                    err: listDetectorsErr
                },
            },
            getDetector: {
                'us-east-1': {
                    [detectorId]: {
                        data: getDetector,
                        err: getDetectorErr
                    }
                }
            },
            listFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: listFindings
                    }
                }
            },
            getFindings: {
                'us-east-1': {
                    [detectorId]: {
                        data: getFindings
                    }
                }
            }
        }
    };
};

describe('noActiveFindings', function () {
    describe('run', function () {
        it('should FAIL if GuardDuty has more than 1 active finding(s)', function (done) {
            const cache = createCache(listDetectors, getDetector, listFindings, getFindings[0]);
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if GuardDuty has 0 active finding(s)', function (done) {
            const cache = createCache(listDetectors, getDetector, listFindings, getFindings[1]);
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no detectors found', function (done) {
            const cache = createCache([]);
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no findings available', function (done) {
            const cache = createCache(listDetectors, getDetector, listFindings, { Findings: [] });
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN unable to list GuardDuty detectors', function (done) {
            const cache = createCache(listDetectors, getDetector, listFindings, { Findings: [] }, { message: 'Unable to find data' });
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN unable to get GuardDuty detector', function (done) {
            const cache = createCache(listDetectors, getDetector, listFindings, { Findings: [] }, null, { message: 'Unable to find data' });
            noActiveFindings.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});