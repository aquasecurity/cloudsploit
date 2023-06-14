var expect = require('chai').expect;
var s3ProtectionEnabled = require('./s3ProtectionEnabled');

const listDetectors = [
    "6cc45a4adb18e50f5ba51f6800db03d8"
];

const getDetector = [
    {
        "CreatedAt": "2021-11-16T15:54:17.530Z",
        "FindingPublishingFrequency": "SIX_HOURS",
        "ServiceRole": "arn:aws:iam::000011112222:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        "Status": "ENABLED",
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
    },
    {
        "CreatedAt": "2021-11-16T15:54:17.530Z",
        "FindingPublishingFrequency": "SIX_HOURS",
        "ServiceRole": "arn:aws:iam::000011112222:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
        "Status": "ENABLED",
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
            "Status": "DISABLED"
          }
        },
        "Tags": {}
    }
];

const createCache = (listDetectors, getDetector) => {
    let detectorId = (listDetectors.length) ? listDetectors[0] : null;
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    data: listDetectors
                },
            },
            getDetector: {
                'us-east-1': {
                    [detectorId]: {
                        data: getDetector
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': {
                    err: {
                        message: 'error desribing cache clusters'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        guardduty: {
            listDetectors: {
                'us-east-1': null
            }
        }
    };
};


describe('s3ProtectionEnabled', function () {
    describe('run', function () {
        it('should FAIL if GuardDuty S3 protection is diabled', function (done) {
            const cache = createCache(listDetectors, getDetector[1],);
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('GuardDuty S3 protection is disabled');
                done();
            });
        });

        it('should PASS if GuardDuty S3protection is enabled', function (done) {
            const cache = createCache(listDetectors, getDetector[0]);
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('GuardDuty S3 protection is enabled');
                done();
            });
        });

        it('should PASS if no detectors found', function (done) {
            const cache = createCache([]);
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No GuardDuty detectors found');
                done();
            });
        });

        it('should UNKNOWN unable to list GuardDuty detector', function (done) {
            const cache = createErrorCache();
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list GuardDuty detectors:');
                done();
            });
        });

        it('should UNKNOWN unable to get GuardDuty detector', function (done) {
            const cache = createCache([listDetectors]);
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to get GuardDuty detector: ');
                done();
            });
        });

        it('should not return any result if list dectectors response not found', function (done) {
            const cache = createNullCache();
            s3ProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});

