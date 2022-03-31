var expect = require('chai').expect;
const vpcFlowLogsMetricAlarm = require('./vpcFlowLogsMetricAlarm');

const describeMetricFilters =  [
    {
        "filterName": "mine1",
        "metricTransformations": [
            {
                "metricName": "cc-vpc-flow-log-metric",
                "metricNamespace": "LogMetrics",
                "metricValue": "1"
            }
        ],
        "creationTime": 1646064572235,
        "logGroupName": "vpc_flow_log_group_name"
    },
    {
        "filterName": "mine1",
        "metricTransformations": [
            {
                "metricName": "cdc-vpc-flow-log-metric",
                "metricNamespace": "LogMetrics",
                "metricValue": "1"
            }
        ],
        "creationTime": 1646064572235,
        "logGroupName": "vpdc_flow_log_group_name"
    }
];

const describeAlarms = [
    {
        "AlarmName": "vpc_flow_log_alarm",
        "AlarmArn": "arn:aws:cloudwatch:us-east-1:000011112222:alarm:vpc_flow_log_alarm",
        "AlarmDescription": "Triggered by 'REJECT' packets.",
        "AlarmConfigurationUpdatedTimestamp": "2022-02-28T16:16:32.485000+00:00",
        "ActionsEnabled": true,
        "OKActions": [],
        "AlarmActions": [
            "arn:aws:sns:us-east-1:000011112222:cc-vpc-flow-log-notifications"
        ],
        "InsufficientDataActions": [],
        "StateValue": "INSUFFICIENT_DATA",
        "StateReason": "Unchecked: Initial alarm creation",
        "StateUpdatedTimestamp": "2022-02-28T16:16:32.485000+00:00",
        "MetricName": "cc-vpc-flow-log-metric",
        "Namespace": "LogMetrics",
        "Statistic": "Sum",
        "Dimensions": [],
        "Period": 300,
        "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1,
        "Threshold": 1.0,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold",
        "TreatMissingData": "missing"
    },
    {
        "AlarmName": "vpd_flow_log_alarm",
        "AlarmArn": "arn:aws:cloudwatch:us-east-1:000011112222:alarm:vpd_flow_log_alarm",
        "AlarmDescription": "Triggered by 'REJECT' packets.",
        "AlarmConfigurationUpdatedTimestamp": "2022-02-28T16:16:32.485000+00:00",
        "ActionsEnabled": true,
        "OKActions": [],
        "AlarmActions": [
            "arn:aws:sns:us-east-1:000011112222:cc-vpc-flow-log-notifications"
        ],
        "InsufficientDataActions": [],
        "StateValue": "INSUFFICIENT_DATA",
        "StateReason": "Unchecked: Initial alarm creation",
        "StateUpdatedTimestamp": "2022-02-28T16:16:32.485000+00:00",
        "MetricName": "cdcc-vpc-flow-log-metric",
        "Namespace": "LogMetrics",
        "Statistic": "Sum",
        "Dimensions": [],
        "Period": 300,
        "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1,
        "Threshold": 1.0,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold",
        "TreatMissingData": "missing"
    },
];

const createCache = (metrics, alarms) => {
    return {
        cloudwatchlogs: {
            describeMetricFilters: {
                'us-east-1': {
                    data: metrics
                },
            },
        },
        cloudwatch: {
            describeAlarms: {
                'us-east-1': { 
                    data: alarms
                }
            },
        },
    };
};

const createErrorCache = () => {
    return {
        cloudwatchlogs: {
            describeMetricFilters: {
                'us-east-1': {
                    err: {
                        message: 'error describing metric filters'
                    },
                },
            },
        cloudwatch:{
            describeAlarms: {
                'us-east-1': {
                        message: 'error describing metric filters alarm'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        cloudwatchlogs: {
            describeMetricFilters: {
                'us-east-1': null,
            },
        },
        cloudwatch: {
            describeAlarms: {
                'us-east-1': null
            },
        },
    };
};


describe('vpcFlowLogsMetricAlarm', function () {
    describe('run', function () {
        it('should PASS if CloudWatch alarm is configured for the VPC Flow Logs', function (done) {
            const cache = createCache([describeMetricFilters[0]], [describeAlarms[0]]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('CloudWatch alarm is configured for VPC flow logs and has an SNS topic attached for notifications')
                done();
            });
        });
        
        it('should FAIL if CloudWatch alarm is not configured for the VPC Flow Logs', function (done) {
            const cache = createCache([describeMetricFilters[0]], [describeAlarms[1]]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CloudWatch alarm is not configured for the VPC flow logs')
                done();
            });
        });
        
        it('should FAIL if no CloudWatch metric alarms found', function (done) {
            const cache = createCache([describeMetricFilters[0]],[]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No CloudWatch metric alarms found')
                done();
            });
        });
        
        it('should UNKNOWN if Unable to query for CloudWatch metric alarms', function (done) {
            const cache = createCache([describeMetricFilters[0]]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for CloudWatch metric alarms')
                done();
            });
        });

        it('should FAIL if Unable to locate the specified log group', function (done) {
            const cache = createCache([describeMetricFilters[1]], describeAlarms[1]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Unable to locate the specified log group')
                done();
            });
        });

        it('should FAIL if No CloudWatch logs metric filters found', function (done) {
            const cache = createCache([]);
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No CloudWatch logs metric filters found')
                done();
            });
        });

        it('should UNKNOWN if Unable to describe CloudWatch logs metric filters', function (done) {
            const cache = createErrorCache();
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to describe CloudWatch logs metric filters')
                done();
            });
        });

        it('should not return anything if describe CloudWatch logs metric filters response not found', function (done) {
            const cache = createNullCache();
            vpcFlowLogsMetricAlarm.run(cache, { vpc_flow_log_group: 'vpc_flow_log_group_name' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return anything if log group name is not provided in settings', function (done) {
            const cache = createNullCache();
            vpcFlowLogsMetricAlarm.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
