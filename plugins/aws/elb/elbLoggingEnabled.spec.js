var expect = require('chai').expect;
const elbLoggingEnabled = require('./elbLoggingEnabled');

const describeLoadBalancers = [
    {
        "LoadBalancerName": "test-84",
        "DNSName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "test-84-1988801627.us-east-1.elb.amazonaws.com",
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
                    "AWSConsole-SSLNegotiationPolicy-test-84-2-1601842068416"
                ]
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
        "Instances": [
            {
                "InstanceId": "i-093267d7a579c4bee",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-0f1f6b356026abc86",
                    "LaunchTemplateName": "auto-scaling-template",
                    "Version": "1"
                },
                "ProtectedFromScaleIn": false
            }
        ],
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

const describeLoadBalancerAttributes = [
    {
        "LoadBalancerAttributes": {
            "CrossZoneLoadBalancing": {
                "Enabled": true
            },
            "AccessLog": {
                "Enabled": true
            },
            "ConnectionDraining": {
                "Enabled": true,
                "Timeout": 300
            },
            "ConnectionSettings": {
                "IdleTimeout": 60
            },
            "AdditionalAttributes": [
                {
                    "Key": "elb.http.desyncmitigationmode",
                    "Value": "defensive"
                }
            ]
        },
    },
    {
        "LoadBalancerAttributes": {
            "CrossZoneLoadBalancing": {
                "Enabled": true
            },
            "AccessLog": {
                "Enabled": false
            },
            "ConnectionDraining": {
                "Enabled": true,
                "Timeout": 300
            },
            "ConnectionSettings": {
                "IdleTimeout": 60
            },
            "AdditionalAttributes": [
                {
                    "Key": "elb.http.desyncmitigationmode",
                    "Value": "defensive"
                }
            ]
        },
    }
];

const createCache = (elb, attributes) => {
    var dnsName = (elb && elb.length && elb[0].DNSName) ? elb[0].DNSName : null;
    return {
        elb:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elb
                },
            },
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    [dnsName]: {
                        data: attributes
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
            describeLoadBalancerAttributes: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancer attributes'
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
            describeLoadBalancerAttributes: {
                'us-east-1': null,
            },
        },
    };
};


describe('elbLoggingEnabled', function () {
    describe('run', function () {
        it('should PASS if logging is enabled for ELB', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[0]);
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if logging is not enabled for ELB', function (done) {
            const cache = createCache([describeLoadBalancers[0]], describeLoadBalancerAttributes[1]);
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        
        it('should PASS if no load balancers present', function (done) {
            const cache = createCache([]);
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to query for load balancers', function (done) {
            const cache = createErrorCache();
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
        
        it('should not return anything if describe load balancers response not found', function (done) {
            const cache = createNullCache();
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return anything if describe load balancer attributes response not found', function (done) {
            const cache = createCache([describeLoadBalancers[0]]);
            elbLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});