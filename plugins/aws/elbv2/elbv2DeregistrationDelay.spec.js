const expect = require('chai').expect;
var elbv2DeregistrationDelay = require('./elbv2DeregistrationDelay');

const describeTargetGroups = [
    {
        "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/temp-tg/fee5b45af37af625",
        "TargetGroupName": "temp-tg",
        "Protocol": "HTTP",
        "Port": 80,
        "VpcId": "vpc-99de2fe4",
        "HealthCheckProtocol": "HTTP",
        "HealthCheckPort": "traffic-port",
        "HealthCheckEnabled": true,
        "HealthCheckIntervalSeconds": 30,
        "HealthCheckTimeoutSeconds": 5,
        "HealthyThresholdCount": 5,
        "UnhealthyThresholdCount": 2,
        "HealthCheckPath": "/",
        "Matcher": {
            "HttpCode": "200"
        },
        "LoadBalancerArns": [
            "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-43/c87a998367b02304"
        ],
        "TargetType": "instance",
        "ProtocolVersion": "HTTP1"
    }
];

const describeTargetGroupAttributes = [
    {
        "Attributes": [
            {
                "Key": "stickiness.enabled",
                "Value": "false"
            },
            {
                "Key": "deregistration_delay.timeout_seconds",
                "Value": "300"
            },
            {
                "Key": "stickiness.type",
                "Value": "lb_cookie"
            },
            {
                "Key": "stickiness.lb_cookie.duration_seconds",
                "Value": "86400"
            },
            {
                "Key": "slow_start.duration_seconds",
                "Value": "0"
            },
            {
                "Key": "load_balancing.algorithm.type",
                "Value": "round_robin"
            }
        ]
    },
    {
        "Attributes": [
            {
                "Key": "stickiness.enabled",
                "Value": "false"
            },
            {
                "Key": "stickiness.type",
                "Value": "lb_cookie"
            },
            {
                "Key": "stickiness.lb_cookie.duration_seconds",
                "Value": "86400"
            },
            {
                "Key": "slow_start.duration_seconds",
                "Value": "0"
            },
            {
                "Key": "load_balancing.algorithm.type",
                "Value": "round_robin"
            }
        ]
    }
];

const createCache = (describeTargetGroups, describeTargetGroupAttributes, describeTargetGroupsErr, describeTargetGroupAttributesErr) => {
    var targetGroupArn = (describeTargetGroups && describeTargetGroups.length) ? describeTargetGroups[0].TargetGroupArn : null;

    return {
        elbv2: {
            describeTargetGroups: {
                'us-east-1': {
                    err: describeTargetGroupsErr,
                    data: describeTargetGroups
                }
            },
            describeTargetGroupAttributes: {
                'us-east-1': {
                    [targetGroupArn]: {
                        err: describeTargetGroupAttributesErr,
                        data: describeTargetGroupAttributes
                    }
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeTargetGroups: {
                'us-east-1': null
            }
        }
    };
};


describe('elbv2DeregistrationDelay', function () {
    describe('run', function () {
        it('should PASS if ELBv2 target group has deregistration delay configured', function (done) {
            const cache = createCache([describeTargetGroups[0]], describeTargetGroupAttributes[0], null, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if ELBv2 target group does not have deregistration delay configured', function (done) {
            const cache = createCache([describeTargetGroups[0]], describeTargetGroupAttributes[1], null, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no ELBv2 target groups found', function (done) {
            const cache = createCache([]);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for ELBv2 target groups', function (done) {
            const cache = createCache([describeTargetGroups[0]], null, { message: "Unable to describe target groups" }, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for ELBv2 target group attributes', function (done) {
            const cache = createCache([describeTargetGroups[0]], describeTargetGroupAttributes[0], null, { message: "Unable to describe target group attributes" });
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe target groups response is not found', function (done) {
            const cache = createNullCache();
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});