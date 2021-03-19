var expect = require('chai').expect;
const elbv2NoInstances = require('./elbv2NoInstances');

const describeLoadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:000011112222:loadbalancer/app/elbv2-1/b5b5c5e457722035",
        "DNSName": "elbv2-1-866927309.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2021-01-07T14:56:37.620Z",
        "LoadBalancerName": "elbv2-1",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "provisioning"
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
                "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:000011112222:targetgroup/temp-tg/fee5b45af37af625",
                "TargetGroupName": "temp-tg",
                "Protocol": "HTTP",
                "Port": 80,
                "VpcId": "vpc-99de2fe4",
                "Matcher": {
                    "HttpCode": "200"
                },
                "LoadBalancerArns": [
                    "arn:aws:elasticloadbalancing:us-east-1:000011112222:loadbalancer/app/elbv2-1/b5b5c5e457722035"
                ],
                "TargetType": "instance"
            }
        ]
    },
    {
        "TargetGroups": []
    }
];

const createCache = (elb, tg, elbErr) => {
    var dnsName = (elb && elb.length) ? elb[0].DNSName : null;
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    err: elbErr,
                    data: elb
                },
            },
            describeTargetGroups: {
                'us-east-1': {
                    [dnsName]: {
                        data: tg
                    }
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2NoInstances', function () {
    describe('run', function () {
        it('should PASS if ELB has target groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[0]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if ELB does not have target groups', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeTargetGroups[1]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no load balancers present', function (done) {
            const cache = createCache([]);
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query for load balancers', function (done) {
            const cache = createCache(describeLoadBalancers[0], describeTargetGroups[0], { message: 'Unable to query load balancers'});
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe load balancers response not found', function (done) {
            const cache = createNullCache();
            elbv2NoInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});