var expect = require('chai').expect;
const webTierIamRole = require('./webTierIamRole');

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
        "AutoScalingGroupName": "test3-36",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:112233445566:autoScalingGroup:d4c0bbe4-e7d6-4d9b-89f1-06021f06a117:autoScalingGroupName/test3-36",
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
            "us-east-1d",
            "us-east-1e"
        ],
        "LoadBalancerNames": [],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [
            {
                "InstanceId": "i-0e8e9dd1aae06d4ae",
                "InstanceType": "t2.micro",
                "AvailabilityZone": "us-east-1e",
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
        "CreatedTime": "2020-09-27T00:01:54.103Z",
    }
];

const describeLaunchConfigurations = [
    {
        "LaunchConfigurationName": "test-lc-43",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:f20acca0-07b4-4cec-9174-75547b193446:launchConfigurationName/test-lc-43",
        "ImageId": "ami-02354e95b39ca8dec",
        "KeyName": "auto-scaling-test-instance",
        "SecurityGroups": [
            "sg-06cccc47e5b3e1ee9"
        ],
        "ClassicLinkVPCSecurityGroups": [],
        "UserData": "",
        "InstanceType": "t2.micro",
        "KernelId": "",
        "RamdiskId": "",
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {
                    "SnapshotId": "snap-06d919bfeced8496a",
                    "VolumeSize": 8,
                    "VolumeType": "gp2",
                    "DeleteOnTermination": true,
                    "Encrypted": false
                }
            }
        ],
        "InstanceMonitoring": {
            "Enabled": false
        },
        "IamInstanceProfile": "arn:aws:iam::111122223333:instance-profile/aws-elasticbeanstalk-ec2-role",
        "CreatedTime": "2020-08-30T22:49:13.182Z",
        "EbsOptimized": false
    },
    {
        "LaunchConfigurationName": "test-lc-43",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:f20acca0-07b4-4cec-9174-75547b193446:launchConfigurationName/test-lc-43",
        "ImageId": "ami-02354e95b39ca8dec",
        "KeyName": "auto-scaling-test-instance",
        "SecurityGroups": [
            "sg-06cccc47e5b3e1ee9"
        ],
        "ClassicLinkVPCSecurityGroups": [],
        "UserData": "",
        "InstanceType": "t2.micro",
        "KernelId": "",
        "RamdiskId": "",
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {
                    "SnapshotId": "snap-06d919bfeced8496a",
                    "VolumeSize": 8,
                    "VolumeType": "gp2",
                    "DeleteOnTermination": true,
                    "Encrypted": false
                }
            }
        ],
        "InstanceMonitoring": {
            "Enabled": false
        },
        "IamInstanceProfile": "",
        "CreatedTime": "2020-08-30T22:49:13.182Z",
        "EbsOptimized": false
    }
];

const createCache = (asg, configuration) => {
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asg
                },
            },
            describeLaunchConfigurations: {
                'us-east-1': {
                        data: configuration 
                }
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
            describeLaunchConfigurations: {
                'us-east-1': {
                    err: {
                        message: 'error describing Auto Scaling Launch Configurations'
                    }
                }
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
            describeLaunchConfigurations: {
                'us-east-1': null,
            },
        },
    };
};

describe('webTierIamRole', function () {
    describe('run', function () {
        it('should PASS if launch configuration for Web-Tier group has customer IAM role configured', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], [describeLaunchConfigurations[0]]);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if launch configuration for Web-Tier group does not have customer IAM role configured', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], [describeLaunchConfigurations[1]]);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Auto Scaling groups found', function (done) {
            const cache = createCache([]);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Auto Scaling groups utilizing launch configurations found', function (done) {
            const cache = createCache([describeAutoScalingGroups[2]], [describeLaunchConfigurations[0]]);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Web-Tier Auto Scaling groups found', function (done) {
            const cache = createCache([describeAutoScalingGroups[3]], [describeLaunchConfigurations[0]]);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Auto Scaling launch configurations found', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], []);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Auto Scaling groups', function (done) {
            const cache = createErrorCache();
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Auto Scaling launch configurations', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], null);
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });        

        it('should not return anything if no response for describe Auto Scaling groups', function (done) {
            const cache = createNullCache();
            webTierIamRole.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});