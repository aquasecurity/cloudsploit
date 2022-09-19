var expect = require('chai').expect;
const elbv2LoggingEnabled = require('./elbv2LoggingEnabled');

const loadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-lb-43/8e680c7bace394a7",
        "DNSName": "test-lb-43-148538634.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2020-08-30T22:55:21.030Z",
        "LoadBalancerName": "test-lb-43",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1c",
                "SubnetId": "subnet-aac6b3e7",
                "LoadBalancerAddresses": []
            },
            {
                "ZoneName": "us-east-1d",
                "SubnetId": "subnet-e83690b7",
                "LoadBalancerAddresses": []
            }
        ],
        "SecurityGroups": [
            "sg-06cccc47e5b3e1ee9"
        ],
        "IpAddressType": "ipv4"
    }
];

const loadBalancerAttributes = [
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "true"
            },        
        ]
    },
    {
        "Attributes": [
            {
                "Key": "access_logs.s3.enabled",
                "Value": "false"
            },
        ]
    }
];

const createCache = (elbv2, attribute) => {
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    [elbv2[0].DNSName]: {
                        data: attribute
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing classic load balancers'
                    },
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing application/network load balancers'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
            describeLoadBalancerAttributes: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbv2LoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if load balancer has Logging enabled', function (done) {
            const cache = createCache([loadBalancers[0]], loadBalancerAttributes[0]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Logging enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if load balancer does not have Logging enabled', function (done) {
            const cache = createCache([loadBalancers[0]], loadBalancerAttributes[1]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Logging not enabled');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if no load balancer attributes found', function (done) {
            const cache = createCache([loadBalancers[0]],[]);
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('no load balancer attributes found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should UNKNOWN if error while describing load balancers', function (done) {
            const cache = createErrorCache();
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for load balancers');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should not return anything if unable to describe load balancers', function (done) {
            const cache = createNullCache();
            elbv2LoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
        
    });
});
