var expect = require('chai').expect;
const organizationChangesAlarm = require('./organizationChangesAlarm');

const describeAlarmForOrgEventsMetric = [
    {
        "AlarmName": "OrganizationsChangesAlarm",
        "AlarmArn": "arn:aws:cloudwatch:us-east-1:000011112222:alarm:OrganizationsChangesAlarm",
        "AlarmDescription": "Triggered by AWS Organizations events.",
        "AlarmConfigurationUpdatedTimestamp": "2022-02-28T13:26:58.719000+00:00",
        "ActionsEnabled": true,
        "OKActions": [],
        "AlarmActions": [
            "arn:aws:sns:us-east-1:000011112222:OrganizationChangesAlarmSNSTopic"
        ],
        "InsufficientDataActions": [],
        "StateValue": "INSUFFICIENT_DATA",
        "StateReason": "Unchecked: Initial alarm creation",
        "StateUpdatedTimestamp": "2022-02-28T13:00:51.094000+00:00",
        "MetricName": "OrganizationsEvents",
        "Namespace": "CloudTrailMetrics",
        "Statistic": "Sum",
        "Dimensions": [],
        "Period": 300,
        "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1,
        "Threshold": 1.0,
        "ComparisonOperator": "LessThanOrEqualToThreshold",
        "TreatMissingData": "missing"
    },
    {}
];

const createCache = (data, err) => {
    return {
        cloudwatch: {
            describeAlarmForOrgEventsMetric: {
                'us-east-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        cloudwatch: {
            describeAlarmForOrgEventsMetric: {
                'us-east-1': null
            }
        }
    }
};

describe('organizationChangesAlarm', function () {
    describe('run', function () {
        it('should PASS if Alarms detecting changes in Amazon Organizations are enabled', function (done) {
            const cache = createCache([describeAlarmForOrgEventsMetric[0]]);
            organizationChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Alarms detecting changes in Amazon Organizations are not enabled', function (done) {
            const cache = createCache(describeAlarmForOrgEventsMetric[1]);
            organizationChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list CloudWatch metric alarms', function (done) {
            const cache = createCache(describeAlarmForOrgEventsMetric, { message: 'unable to list CloudWatch metric alarms' });
            organizationChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list CloudWatch metric alarms response not found', function (done) {
            const cache = createNullCache();
            organizationChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
