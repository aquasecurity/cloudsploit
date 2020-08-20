var expect = require('chai').expect;
const asgMissingELB = require('./asgMissingELB');

const autoScalingGroups =  [
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:560213429563:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
        "LaunchTemplate": {
            "LaunchTemplateId": "lt-0f1f6b356026abc86",
            "LaunchTemplateName": "auto-scaling-template",
            "Version": "$Default"
        },
        "MinSize": 1,
        "MaxSize": 1,
        "DesiredCapacity": 1,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": ["my-load-balancer", "my-load-balancer2"],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
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
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "SuspendedProcesses": [],
        "VPCZoneIdentifier": "subnet-06aa0f60",
        "EnabledMetrics": [],
        "Tags": [],
        "TerminationPolicies": [
            "Default"
        ],
        "NewInstancesProtectedFromScaleIn": false,
        "ServiceLinkedRoleARN": "arn:aws:iam::560213429563:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:560213429563:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
        "LaunchTemplate": {
            "LaunchTemplateId": "lt-0f1f6b356026abc86",
            "LaunchTemplateName": "auto-scaling-template",
            "Version": "$Default"
        },
        "MinSize": 1,
        "MaxSize": 1,
        "DesiredCapacity": 1,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": ['my-load-balancer'],
        "TargetGroupARNs": [],
        "HealthCheckType": "ELB",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2020-08-18T23:12:00.954Z",
        "SuspendedProcesses": [],
        "VPCZoneIdentifier": "subnet-06aa0f60",
        "EnabledMetrics": [],
        "Tags": [],
        "TerminationPolicies": [
            "Default"
        ],
        "NewInstancesProtectedFromScaleIn": false,
        "ServiceLinkedRoleARN": "arn:aws:iam::560213429563:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
];

const loadBalancers = [
    {
        "LoadBalancerDescriptions": [
            {
            "AvailabilityZones": [
                "us-west-2a"
            ], 
            "BackendServerDescriptions": [
                {
                    "InstancePort": 80, 
                    "PolicyNames": [
                        "my-ProxyProtocol-policy"
                    ]
                }
            ], 
            "CanonicalHostedZoneName": "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com", 
            "CanonicalHostedZoneNameID": "Z3DZXE0EXAMPLE", 
            "CreatedTime": "2020-08-18T23:12:00.954Z", 
            "DNSName": "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com", 
            "HealthCheck": {
                "HealthyThreshold": 2, 
                "Interval": 30, 
                "Target": "HTTP:80/png", 
                "Timeout": 3, 
                "UnhealthyThreshold": 2
            }, 
            "Instances": [
                {
                    "InstanceId": "i-207d9717"
                }, 
                {
                "InstanceId": "i-afefb49b"
                }
            ], 
            "ListenerDescriptions": [
                {
                    "Listener": {
                        "InstancePort": 80, 
                        "InstanceProtocol": "HTTP", 
                        "LoadBalancerPort": 80, 
                        "Protocol": "HTTP"
                    }, 
                    "PolicyNames": [
                    ]
                }, 
                {
                    "Listener": {
                        "InstancePort": 443, 
                        "InstanceProtocol": "HTTPS", 
                        "LoadBalancerPort": 443, 
                        "Protocol": "HTTPS", 
                        "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-cert"
                    }, 
                    "PolicyNames": [
                        "ELBSecurityPolicy-2015-03"
                    ]
                }
            ], 
            "LoadBalancerName": "my-load-balancer", 
            "Policies": {
                "AppCookieStickinessPolicies": [
                ], 
                "LBCookieStickinessPolicies": [
                    {
                        "CookieExpirationPeriod": 60, 
                        "PolicyName": "my-duration-cookie-policy"
                    }
                ], 
                "OtherPolicies": [
                    "my-PublicKey-policy", 
                    "my-authentication-policy", 
                    "my-SSLNegotiation-policy", 
                    "my-ProxyProtocol-policy", 
                    "ELBSecurityPolicy-2015-03"
                ]
            }, 
            "Scheme": "internet-facing", 
            "SecurityGroups": [
                "sg-a61988c3"
            ], 
            "SourceSecurityGroup": {
                "GroupName": "my-elb-sg", 
                "OwnerAlias": "123456789012"
            }, 
            "Subnets": [
                "subnet-15aaab61"
            ], 
            "VPCId": "vpc-a01106c2"
            }
        ]
    },
    {
        "LoadBalancerDescriptions": [
            {
            "AvailabilityZones": [
                "us-west-2a"
            ], 
            "BackendServerDescriptions": [
                {
                    "InstancePort": 80, 
                    "PolicyNames": [
                        "my-ProxyProtocol-policy"
                    ]
                }
            ], 
            "CanonicalHostedZoneName": "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com", 
            "CanonicalHostedZoneNameID": "Z3DZXE0EXAMPLE", 
            "CreatedTime": "2020-08-18T23:12:00.954Z", 
            "DNSName": "my-load-balancer-1234567890.us-west-2.elb.amazonaws.com", 
            "HealthCheck": {
                "HealthyThreshold": 2, 
                "Interval": 30, 
                "Target": "HTTP:80/png", 
                "Timeout": 3, 
                "UnhealthyThreshold": 2
            }, 
            "Instances": [
                {
                    "InstanceId": "i-207d9717"
                }, 
                {
                "InstanceId": "i-afefb49b"
                }
            ], 
            "ListenerDescriptions": [
                {
                    "Listener": {
                        "InstancePort": 80, 
                        "InstanceProtocol": "HTTP", 
                        "LoadBalancerPort": 80, 
                        "Protocol": "HTTP"
                    }, 
                    "PolicyNames": [
                    ]
                }, 
                {
                    "Listener": {
                        "InstancePort": 443, 
                        "InstanceProtocol": "HTTPS", 
                        "LoadBalancerPort": 443, 
                        "Protocol": "HTTPS", 
                        "SSLCertificateId": "arn:aws:iam::123456789012:server-certificate/my-server-cert"
                    }, 
                    "PolicyNames": [
                        "ELBSecurityPolicy-2015-03"
                    ]
                }
            ], 
            "LoadBalancerName": "my-load-balancer", 
            "Policies": {
                "AppCookieStickinessPolicies": [
                ], 
                "LBCookieStickinessPolicies": [
                    {
                        "CookieExpirationPeriod": 60, 
                        "PolicyName": "my-duration-cookie-policy"
                    }
                ], 
                "OtherPolicies": [
                    "my-PublicKey-policy", 
                    "my-authentication-policy", 
                    "my-SSLNegotiation-policy", 
                    "my-ProxyProtocol-policy", 
                    "ELBSecurityPolicy-2015-03"
                ]
            }, 
            "Scheme": "internet-facing", 
            "SecurityGroups": [
                "sg-a61988c3"
            ], 
            "SourceSecurityGroup": {
                "GroupName": "my-elb-sg", 
                "OwnerAlias": "123456789012"
            }, 
            "Subnets": [
                "subnet-15aaab61"
            ], 
            "VPCId": "vpc-a01106c2"
            }
        ]
    },
];


const createCache = (asgs, elb) => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asgs
                },
            },
            describeLoadBalancers: {
                'us-east-1': {
                    [asgs[0].LoadBalancerNames]: {
                        data: elb
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing autoscaling groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('asgMissingELB', function () {
    describe('run', function () {
        it('should PASS if autoscaling group utilizes active load balancer', function (done) {
            const cache = createCache([autoScalingGroups[1]], loadBalancers[0]);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if autoscaling group does not utilizes active load balancer', function (done) {
            const cache = createCache([autoScalingGroups[1]], []);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe autoscaling group found', function (done) {
            const cache = createErrorCache();
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no autoscaling group found', function (done) {
            const cache = createNullCache();
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});