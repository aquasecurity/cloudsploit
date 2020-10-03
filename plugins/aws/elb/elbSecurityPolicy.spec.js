var expect = require('chai').expect;
const elbSecurityPolicy = require('./elbSecurityPolicy');

const describeLoadBalancers = [
    {
        "LoadBalancerName": "test-84-2",
        "DNSName": "test-84-2-31381010.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-2-31381010.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "HTTPS",
                    "LoadBalancerPort": 443,
                    "InstanceProtocol": "HTTPS",
                    "InstancePort": 443,
                    "SSLCertificateId": "arn:aws:iam::111122223333:server-certificate/ExampleCertificate"
                },
                "PolicyNames": [
                    "AWSConsole-SSLNegotiationPolicy-test-84-2-1601575981803"
                ]
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": [
                "AWSConsole-SSLNegotiationPolicy-test-84-2-1601575981803",
                "ELBSecurityPolicy-2016-08"
            ]
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [],
        "HealthCheck": {
            "Target": "HTTPS:443/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T18:13:00.580Z",
        "Scheme": "internet-facing"
    },
    {
        "LoadBalancerName": "test-84",
        "DNSName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
            {
                "Listener": {
                    "Protocol": "TCP",
                    "LoadBalancerPort": 82,
                    "InstanceProtocol": "TCP",
                    "InstancePort": 82
                },
                "PolicyNames": []
            },
            {
                "Listener": {
                    "Protocol": "HTTP",
                    "LoadBalancerPort": 80,
                    "InstanceProtocol": "HTTP",
                    "InstancePort": 80
                },
                "PolicyNames": []
            }
        ],
        "Policies": {
            "AppCookieStickinessPolicies": [],
            "LBCookieStickinessPolicies": [],
            "OtherPolicies": []
        },
        "BackendServerDescriptions": [],
        "AvailabilityZones": [
            "us-east-1f",
            "us-east-1e",
            "us-east-1d",
            "us-east-1c",
            "us-east-1b",
            "us-east-1a"
        ],
        "Subnets": [
            "subnet-06aa0f60",
            "subnet-673a9a46",
            "subnet-6a8b635b",
            "subnet-aac6b3e7",
            "subnet-c21b84cc",
            "subnet-e83690b7"
        ],
        "VPCId": "vpc-99de2fe4",
        "Instances": [],
        "HealthCheck": {
            "Target": "HTTP:80/index.html",
            "Interval": 30,
            "Timeout": 5,
            "UnhealthyThreshold": 2,
            "HealthyThreshold": 10
        },
        "SourceSecurityGroup": {
            "OwnerAlias": "111122223333",
            "GroupName": "default"
        },
        "SecurityGroups": [
            "sg-aa941691"
        ],
        "CreatedTime": "2020-10-01T17:50:43.330Z",
        "Scheme": "internet-facing"
    }
];

const describeLoadBalancerPolicies = [
    {
        ResponseMetadata: { RequestId: '4344d6c8-5047-4610-94a4-70ca01fdffc6' },
        PolicyDescriptions: [
            {
                PolicyName: 'AWSConsole-SSLNegotiationPolicy-test-84-2-1601575981803',
                PolicyTypeName: 'SSLNegotiationPolicyType',
                PolicyAttributeDescriptions: [
                    {
                        AttributeName: 'Reference-Security-Policy',
                        AttributeValue: 'ELBSecurityPolicy-2016-08'
                    },
                ],
            },
        ],
    },
    {
        ResponseMetadata: { RequestId: '4344d6c8-5047-4610-94a4-70ca01fdffc6' },
        PolicyDescriptions: [
            {
                PolicyName: 'AWSConsole-SSLNegotiationPolicy-test-84-2-1601575981803',
                PolicyTypeName: 'SSLNegotiationPolicyType',
                PolicyAttributeDescriptions: [
                    {
                        AttributeName: 'Reference-Security-Policy',
                        AttributeValue: 'ELBSecurityPolicy-2015-08'
                    },
                ],
            },
        ],
    },
    {
        ResponseMetadata: { RequestId: '4344d6c8-5047-4610-94a4-70ca01fdffc6' },
        PolicyDescriptions: [
            {
                PolicyName: 'AWSConsole-SSLNegotiationPolicy-test-84-2-1601575981803',
                PolicyTypeName: 'SSLNegotiationPolicyType',
                PolicyAttributeDescriptions: [
                    {
                        AttributeName: 'Policy',
                        AttributeValue: 'ELBSecurityPolicy-2015-08'
                    },
                ],
            },
        ],
    }
];


const createCache = (elb, policy) => {
    if (elb && elb.length) var lbDnsName = elb[0].DNSName;
    return {
        elb:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elb
                },
            },
            describeLoadBalancerPolicies: {
                'us-east-1': {
                    [lbDnsName]: {
                        data: policy
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancers'
                    },
                },
            },
            describeLoadBalancerPolicies: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancer policies'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
            describeLoadBalancerPolicies: {
                'us-east-1': null,
            },
        },
    };
};

describe('elbSecurityPolicy', function () {
    describe('run', function () {
        it('should PASS if load balancer is using latest predefined policies', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerPolicies[0]);
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if load balancer is not using latest predefined policies', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerPolicies[1]);
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if load balancer is not using any reference security policy', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerPolicies[2]);
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancer policies', function (done) {
            const cache = createCache([describeLoadBalancers[0]], null);
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe load balancers', function (done) {
            const cache = createErrorCache();
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe load balancers response is not found', function (done) {
            const cache = createNullCache();
            elbSecurityPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});