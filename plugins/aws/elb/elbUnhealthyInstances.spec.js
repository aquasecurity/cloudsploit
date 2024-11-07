var expect = require('chai').expect;
var elbUnhealthyInstances = require('./elbUnhealthyInstances');

    const describeLoadBalancersData = [
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
                    "LaunchTemplateId": "lt-0f1f6b356027abc86",
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
    }
];
const describeInstanceHealthData = [
    
    {
    InstanceStates: [
        {
            InstanceId: 'instance-id',
            State: 'InService',
            "ReasonCode": "Instance",
            "Description": "N/A"
        }
    ]
},
{
    InstanceStates: [
        {
            InstanceId: 'instance-id',
            State: 'OutOfService',
            "ReasonCode": "Instance",
             "Description": "Instance has failed at least the UnhealthyThreshold number of health checks consecutively."
        }
    ]
},
];

const createCache = (describeLoadBalancersData, describeInstanceHealthData) => {
    var dnsName = (describeLoadBalancersData && describeLoadBalancersData.length) ? describeLoadBalancersData[0].DNSName : null;
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    data: describeLoadBalancersData
                }
            },
            describeInstanceHealth: {
                'us-east-1': {
                    [dnsName]: {
                        data: describeInstanceHealthData
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error fetching load balancers'
                    },
                },
            },
            describeInstanceHealth: {
                'us-east-1': {
                    'elb-dns-name': {
                        err: {
                            message: 'error fetching instance health'
                        },
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        elb: {
            describeLoadBalancers: {
                'us-east-1': null
            },
            describeInstanceHealth: {
                'us-east-1': null
            }
        }
    };
};


describe('elbUnhealthyInstances', function () {
    describe('run', function () {
        it('should return UNKNOWN if unable to query for load balancers', function (done) {
            const cache = createErrorCache();
            elbUnhealthyInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for load balancers:');
                done();
            });
        });

        it('should return PASS if no load balancers are present', function (done) {
            const cache = createCache([]);
            elbUnhealthyInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No load balancers present');
                done();
            });
        });

        it('should return FAIL if ELB has unhealthy instances', function (done) {
            const cache = createCache([describeLoadBalancersData[0]], describeInstanceHealthData[1]);
            elbUnhealthyInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should return PASS if ELB does not have unhealthy instances', function (done) {
            const cache = createCache([describeLoadBalancersData[0]], describeInstanceHealthData[0]);
            elbUnhealthyInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('ELB does not have unhealthy instance');
                done();
            });
        });

        it('should not return anything if describeLoadBalancers response is not found', function (done) {
            const cache = createNullCache();
            elbUnhealthyInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});

