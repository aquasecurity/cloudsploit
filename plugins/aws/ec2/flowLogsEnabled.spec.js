var expect = require('chai').expect;
const flowLogsEnabled = require('./flowLogsEnabled');

const describeVpcs = [
    {
        "CidrBlock": '172.31.0.0/16',
        "DhcpOptionsId": 'dopt-3a821040',
        "State": 'available',
        "VpcId": 'vpc-99de2fe4',
        "OwnerId": '111122223333',
        "InstanceTenancy": 'default',
        "Ipv6CidrBlockAssociationSet": [],
        "CidrBlockAssociationSet": "",
        "IsDefault": true,
        "Tags": []
    }
];

const describeFlowLogs = [
    {
        "CreationTime": '2020-11-10T23:42:32.557Z',
        "DeliverLogsPermissionArn": 'arn:aws:iam::111122223333:role/service-role/test-lambda-role-rewuhg4u',
        "DeliverLogsStatus": 'SUCCESS',
        "FlowLogId": 'fl-0698ebb14b1748a3f',
        "FlowLogStatus": 'ACTIVE',
        "LogGroupName": '/aws/lambda/test-lambda',
        "ResourceId": 'vpc-99de2fe4',
        "TrafficType": 'ACCEPT',
        "LogDestinationType": 'cloud-watch-logs',
        "LogFormat": '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}',
        "Tags": [],
        "MaxAggregationInterval": 600
    },
    {
        "CreationTime": '2020-11-10T23:42:32.557Z',
        "DeliverLogsPermissionArn": 'arn:aws:iam::111122223333:role/service-role/test-lambda-role-rewuhg4u',
        "DeliverLogsStatus": 'SUCCESS',
        "FlowLogId": 'fl-0698ebb14b1748a3f',
        "FlowLogStatus": 'INACTIVE',
        "LogGroupName": '/aws/lambda/test-lambda',
        "ResourceId": 'vpc-99de2fe4',
        "TrafficType": 'ACCEPT',
        "LogDestinationType": 'cloud-watch-logs',
        "LogFormat": '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}',
        "Tags": [],
        "MaxAggregationInterval": 600
    },
];

const createCache = (vpcs, flowlogs) => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': {
                    data: vpcs
                },
            },
            describeFlowLogs: {
                'us-east-1': {
                    data: flowlogs
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': {
                    err: {
                        message: 'error describing vpcs'
                    },
                },
            },
            describeFlowLogs: {
                'us-east-1': {
                    err: {
                        message: 'error describing flowlogs'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeVpcs: {
                'us-east-1': null,
            },
            describeFlowLogs: {
                'us-east-1': null,
            },
        },
    };
};

describe('flowLogsEnabled', function () {
    describe('run', function () {
        it('should PASS if VPC flow logs are enabled', function (done) {
            const cache = createCache([describeVpcs[0]], [describeFlowLogs[0]]);
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if VPC flow logs are enabled, but not active', function (done) {
            const cache = createCache([describeVpcs[0]], [describeFlowLogs[1]]);
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if VPC flow logs are not enabled', function (done) {
            const cache = createCache([describeVpcs[0]], []);
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no VPCs found', function (done) {
            const cache = createCache([]);
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON if unable to describe vpcs', function (done) {
            const cache = createErrorCache();
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNWON if unable to describe flowlogs', function (done) {
            const cache = createCache([describeVpcs[0]], null);
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe vpcs response not found', function (done) {
            const cache = createNullCache();
            flowLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});