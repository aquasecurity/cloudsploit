var expect = require('chai').expect;
const webTierAssociatedElb = require('./webTierAssociatedElb');

const describeAutoScalingGroups =  [
    {
        "AutoScalingGroupName": "test-36",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:d18695a1-726b-4011-9c1e-2f648fccbc26:autoScalingGroupName/test-36",
        "LaunchConfigurationName": "test-lc-43",
        "MinSize": 1,
        "MaxSize": 1,
        "DesiredCapacity": 1,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a"
        ],
        "LoadBalancerNames": ["test-lb"],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-0342dfcfa0469d667",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchConfigurationName": "test-lc-43",
                "ProtectedFromScaleIn": false
            }
        ],
        "CreatedTime": "2020-09-23T22:28:04.892Z",
        "SuspendedProcesses": [],
        "VPCZoneIdentifier": "subnet-06aa0f60",
        "EnabledMetrics": [],
        "Tags": [
            {
                "ResourceId": "test-36",
                "ResourceType": "auto-scaling-group",
                "Key": "web_tier",
                "Value": "web_tier",
                "PropagateAtLaunch": true
            }
        ],
        "TerminationPolicies": [
            "Default"
        ],
        "NewInstancesProtectedFromScaleIn": false,
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    },
    {
        "AutoScalingGroupName": "test-36",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:111122223333:autoScalingGroup:d18695a1-726b-4011-9c1e-2f648fccbc26:autoScalingGroupName/test-36",
        "LaunchConfigurationName": "test-lc-43",
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
        "Instances": [
            {
                "InstanceId": "i-0342dfcfa0469d667",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1a",
                "LifecycleState": "InService",
                "HealthStatus": "Healthy",
                "LaunchConfigurationName": "test-lc-43",
                "ProtectedFromScaleIn": false
            }
        ],
        "CreatedTime": "2020-09-23T22:28:04.892Z",
        "SuspendedProcesses": [],
        "VPCZoneIdentifier": "subnet-06aa0f60",
        "EnabledMetrics": [],
        "Tags": [
            {
                "ResourceId": "test-36",
                "ResourceType": "auto-scaling-group",
                "Key": "web_tier",
                "Value": "web_tier",
                "PropagateAtLaunch": true
            }
        ],
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
    }
];

const createCache = (asg) => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asg
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
                        message: 'error describing Auto Scaling groups'
                    }
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

describe('webTierAssociatedElb', function () {
    describe('run', function () {
        it('should PASS if Web-Tier ASG has ELB associated', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]]);
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Web-Tier ASG does not have ELB associated', function (done) {
            const cache = createCache([describeAutoScalingGroups[1]]);
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Auto Scaling groups found', function (done) {
            const cache = createCache([]);
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Auto Scaling group does not have any Web-Tier tag', function (done) {
            const cache = createCache([describeAutoScalingGroups[2]]);
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error describing Auto Scaling groups', function (done) {
            const cache = createErrorCache();
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });     

        it('should not return anything if unable to describe Auto Scaling groups', function (done) {
            const cache = createNullCache();
            webTierAssociatedElb.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});