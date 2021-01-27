const expect = require('chai').expect;
var elbv2DeregistrationDelay = require('./elbv2DeregistrationDelay');

const describeLoadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/akd-43/c87a998367b02304",
        "DNSName": "akd-43-984137401.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-01-26T05:14:48.430000+00:00",
        "LoadBalancerName": "akd-43",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1a",
                "SubnetId": "subnet-06aa0f60",
                "LoadBalancerAddresses": []
            },
            {
                "ZoneName": "us-east-1b",
                "SubnetId": "subnet-673a9a46",
                "LoadBalancerAddresses": []
            }
        ],
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "IpAddressType": "ipv4"
    }
];

const describeTargetGroups = [
    {
        "TargetGroups": [
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
        ]
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

const createCache = (describeLoadBalancers, describeTargetGroups, describeTargetGroupAttributes, describeLoadBalancersErr, describeTargetGroupsErr, describeTargetGroupAttributesErr) => {
    var dnsName = (describeLoadBalancers && describeLoadBalancers.length) ? describeLoadBalancers[0].DNSName : null;
    var targetGroupArn = (describeTargetGroups && describeTargetGroups.TargetGroups && describeTargetGroups.TargetGroups.length) ? describeTargetGroups.TargetGroups[0].TargetGroupArn : null;

    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: describeLoadBalancersErr,
                    data: describeLoadBalancers
                }
            },
            describeTargetGroups: {
                'us-east-1': {
                    [dnsName]: {
                        err: describeTargetGroupsErr,
                        data: describeTargetGroups
                    }
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
            describeLoadBalancers: {
                'us-east-1': null
            }
        }
    };
};


describe('elbv2DeregistrationDelay', function () {
    describe('run', function () {
        it('should PASS if Application/Network load balancer has deregistration delay configured', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0], describeTargetGroupAttributes[0], null, null, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Application/Network load balancer does not have deregistration delay configured', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0], describeTargetGroupAttributes[1], null, null, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Application/Network load balancers found', function (done) {
            const cache = createCache([]);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if no Application/Network load balancers target groups found', function (done) {
            const cache = createCache([describeLoadBalancers[0]], []);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for Application/Network load balancers', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to describe load balancers" }, null, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for Application/Network load balancer target groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0], null, null, { message: "Unable to describe target groups" }, null);
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query for Application/Network load balancer target group attributes', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0], describeTargetGroupAttributes[0], null, null, { message: "Unable to describe target group attributes" });
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe load balancers response not found', function (done) {
            const cache = createNullCache();
            elbv2DeregistrationDelay.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});