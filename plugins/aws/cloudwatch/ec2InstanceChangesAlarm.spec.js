var expect = require('chai').expect;
const ec2InstanceChangesAlarm = require('./ec2InstanceChangesAlarm');

const describeAlarmForEC2InstanceMetric = [
    {
        "AlarmName": "EC2InstanceChangesAlarm",
        "AlarmArn": "arn:aws:cloudwatch:us-east-1:000011112222:alarm:EC2InstanceChangesAlarm",
        "AlarmDescription": "Triggered by EC2 instances config/status changes.",
        "AlarmConfigurationUpdatedTimestamp": "2022-03-01T16:37:43.981000+00:00",
        "ActionsEnabled": true,
        "OKActions": [],
        "AlarmActions": [
            "arn:aws:sns:us-east-1:000011112222:mine1"
        ],
        "InsufficientDataActions": [],
        "StateValue": "INSUFFICIENT_DATA",
        "StateReason": "Unchecked: Initial alarm creation",
        "StateUpdatedTimestamp": "2022-03-01T16:37:43.981000+00:00",
        "MetricName": "EC2InstanceEventCount",
        "Namespace": "CloudTrailMetrics",
        "Statistic": "Sum",
        "Dimensions": [],
        "Period": 300,
        "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1,
        "Threshold": 1.0,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold",
        "TreatMissingData": "missing"
    },
    {}
];

const createCache = (data, err) => {
    return {
        cloudwatch: {
            describeAlarmForEC2InstanceMetric: {
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
            describeAlarmForEC2InstanceMetric: {
                'us-east-1': null
            }
        }
    }
};

describe('ec2InstanceChangesAlarm', function () {
    describe('run', function () {
        it('should PASS if Alarms detecting changes in EC2 instances are enabled', function (done) {
            const cache = createCache([describeAlarmForEC2InstanceMetric[0]]);
            ec2InstanceChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Alarms detecting changes in EC2 instances are not enabled', function (done) {
            const cache = createCache(describeAlarmForEC2InstanceMetric[1]);
            ec2InstanceChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe CloudWatch metric alarms', function (done) {
            const cache = createCache(describeAlarmForEC2InstanceMetric, { message: 'unable to list CloudWatch metric alarms' });
            ec2InstanceChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list CloudWatch metric alarms response not found', function (done) {
            const cache = createNullCache();
            ec2InstanceChangesAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});