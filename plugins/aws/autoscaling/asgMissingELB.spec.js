var expect = require('chai').expect;
const asgMissingELB = require('./asgMissingELB');

const autoScalingGroups =  [
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
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
        "LoadBalancerNames": ["asgEmptyElb"],
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
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
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
        "LoadBalancerNames": ["my-load-balancer2"],
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
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
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
        "LoadBalancerNames": [],
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
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
    {
        "AutoScalingGroupName": "auto-scaling-test-group",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:e83ceb12-2760-4a92-a374-3df611331bdc:autoScalingGroupName/auto-scaling-test-group",
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
        "LoadBalancerNames": [],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
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
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
];

const loadBalancers = [
    {
        "LoadBalancerName": "asgEmptyElb",
        "DNSName": "asgEmptyElb-1112223333.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneName": "asgEmptyElb-1112223333.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneNameID": "Z35SXDOTRQ7X7K",
        "ListenerDescriptions": [
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
        "Instances": [
            {
                "InstanceId": "i-00178f718e021c46b"
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
        "CreatedTime": "2020-08-26T02:49:20.250Z",
        "Scheme": "internet-facing"
    }
]

const loadBalancersV2 = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/networkELB/2ea2eb9b8d381866",
        "DNSName": "networkELB-2ea2eb9b8d381866.elb.us-east-1.amazonaws.com",
        "CanonicalHostedZoneId": "Z26RNL4JYFTOTI",
        "CreatedTime": "2020-08-26T02:50:34.119Z",
        "LoadBalancerName": "networkELB",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "network",
        "AvailabilityZones": [
            {
                "ZoneName": "us-east-1b",
                "SubnetId": "subnet-673a9a46",
                "LoadBalancerAddresses": []
            },
            {
                "ZoneName": "us-east-1a",
                "SubnetId": "subnet-06aa0f60",
                "LoadBalancerAddresses": []
            }
        ],
        "IpAddressType": "ipv4"
    }

]

const createCache = (asgs, elb, elbv2) => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asgs
                },
            },
        },
        elb:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elb
                },
            },
        },
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
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
                        message: 'error describing AutoScaling groups'
                    },
                },
            },
        },
        elb: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing classic load balancers'
                    },
                },
            },
        },
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing application/network load balancers'
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
        elb: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
        },
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
        },
    };
};


describe('asgMissingELB', function () {
    describe('run', function () {
        it('should PASS if AutoScaling group utilizes active load balancer', function (done) {
            const cache = createCache([autoScalingGroups[0]], [loadBalancers[0]], [loadBalancersV2[0]]);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if AutoScaling group utilizes inactive load balancer', function (done) {
            const cache = createCache([autoScalingGroups[1]], [loadBalancers[0]], [loadBalancersV2[0]]);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if AutoScaling group does not have any ELB associated', function (done) {
            const cache = createCache([autoScalingGroups[2]], [loadBalancers[0]], [loadBalancersV2[0]]);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if AutoScaling group does not utilize a load balancer', function (done) {
            const cache = createCache([autoScalingGroups[3]], [loadBalancers[0]], [loadBalancersV2[0]]);
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should UNKNOWN if unable to describe AutoScaling group found', function (done) {
            const cache = createErrorCache();
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no AutoScaling group found', function (done) {
            const cache = createNullCache();
            asgMissingELB.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});