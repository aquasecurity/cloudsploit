var expect = require('chai').expect;
const webTierAsgCloudWatchLogs = require('./webTierAsgCloudwatchLogs');

const describeAutoScalingGroups =  [
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
        "Tags": [{
            "ResourceId": "test-45",
            "ResourceType": "auto-scaling-group",
            "Key": "web_tier",
            "Value": "",
            "PropagateAtLaunch": true
        }],
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
        "Tags": [{
            "ResourceId": "test-45",
            "ResourceType": "auto-scaling-group",
            "Key": "key_tier",
            "Value": "",
            "PropagateAtLaunch": true
        }],
        "TerminationPolicies": [
            "Default"
        ],
        "NewInstancesProtectedFromScaleIn": false,
        "ServiceLinkedRoleARN": "arn:aws:iam::111122223333:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    }
];

const describeLaunchConfigurations = [
    {
        "LaunchConfigurations": [
            {
                "LaunchConfigurationName": "test-36",
                "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:b7772b0b-5b9e-4fc2-8509-e298fed9fae2:launchConfigurationName/test-36",
                "ImageId": "ami-0001903fe8544444c",
                "KeyName": "auto-scaling-test-instance",
                "SecurityGroups": [
                    "sg-08f7cb8776a0176ef"
                ],
                "ClassicLinkVPCSecurityGroups": [],
                "UserData": "#!/bin/bash curl https://s3.amazonaws.com//aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -O chmod +x ./awslogs-agent-setup.py ./awslogs-agent-setup.py -n -r us-east-1 -c s3://bucket-test-13/configFile.config",
                "InstanceType": "t2.micro",
                "KernelId": "",
                "RamdiskId": "",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {
                            "SnapshotId": "snap-0923e10c79d5bd837",
                            "VolumeSize": 50,
                            "VolumeType": "gp2",
                            "DeleteOnTermination": true,
                            "Encrypted": false
                        }
                    },
                    {
                        "DeviceName": "/dev/sde",
                        "Ebs": {
                            "SnapshotId": "snap-0ac876e65f9c1711c",
                            "VolumeSize": 250,
                            "VolumeType": "gp2",
                            "DeleteOnTermination": false,
                            "Encrypted": false
                        }
                    },
                    {
                        "DeviceName": "/dev/sdc",
                        "NoDevice": true
                    },
                    {
                        "DeviceName": "/dev/sdb",
                        "NoDevice": true
                    }
                ],
                "InstanceMonitoring": {
                    "Enabled": false
                },
                "CreatedTime": "2020-09-24T00:00:29.642Z",
                "EbsOptimized": false
            }
        ]
    },
    {
        "LaunchConfigurations": [
            {
                "LaunchConfigurationName": "test-36",
                "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:b7772b0b-5b9e-4fc2-8509-e298fed9fae2:launchConfigurationName/test-36",
                "ImageId": "ami-0001903fe85445000",
                "KeyName": "auto-scaling-test-instance",
                "SecurityGroups": [
                    "sg-08f7cb8776a0176ef"
                ],
                "ClassicLinkVPCSecurityGroups": [],
                "UserData": "",
                "InstanceType": "t2.micro",
                "KernelId": "",
                "RamdiskId": "",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/sda1",
                        "Ebs": {
                            "SnapshotId": "snap-0923e10c79d5bd837",
                            "VolumeSize": 50,
                            "VolumeType": "gp2",
                            "DeleteOnTermination": true,
                            "Encrypted": false
                        }
                    },
                    {
                        "DeviceName": "/dev/sde",
                        "Ebs": {
                            "SnapshotId": "snap-0ac876e65f9c1711c",
                            "VolumeSize": 250,
                            "VolumeType": "gp2",
                            "DeleteOnTermination": false,
                            "Encrypted": false
                        }
                    },
                    {
                        "DeviceName": "/dev/sdc",
                        "NoDevice": true
                    },
                    {
                        "DeviceName": "/dev/sdb",
                        "NoDevice": true
                    }
                ],
                "InstanceMonitoring": {
                    "Enabled": false
                },
                "CreatedTime": "2020-09-24T00:00:29.642Z",
                "EbsOptimized": false
            }
        ]
    }
];

const createCache = (asgs, config) => {
    var asgArn = (asgs && asgs.length) ? asgs[0].AutoScalingGroupARN : null;
    return {
        autoscaling: {
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: asgs
                },
            },
            describeLaunchConfigurations: {
                'us-east-1': {
                    [asgArn]: {
                        data: config
                    }
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
                        message: 'error describing autos caling groups'
                    },
                },
                describeLaunchConfigurations: {
                    'us-east-1': {
                        message: 'error describing auto scaling group notification configurations'
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
            describeLaunchConfigurations: {
                'us-east-1': null
            },
        },
    };
};


describe('webTierAsgCloudWatchLogs', function () {
    describe('run', function () {
        it('should PASS if Web-Tier Auto Scaling launch configuration has CloudWatch logs enabled', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], describeLaunchConfigurations[0]);
            const settings = { s3_cw_agent_config_file: 's3://bucket-test-13/configFile.config', web_tier_tag_key: 'web_tier' };
            webTierAsgCloudWatchLogs.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Web-Tier Auto Scaling launch configuration does not have CloudWatch logs enabled', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], describeLaunchConfigurations[1]);
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe launch configuration for Web-Tier Auto Scaling group', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]]);
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no Web-Tier Auto Scaling groups found', function (done) {
            const cache = createCache([describeAutoScalingGroups[1]], describeLaunchConfigurations[2]);
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no Auto Scaling groups found', function (done) {
            const cache = createCache([]);
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Auto Scaling groups', function (done) {
            const cache = createErrorCache();
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no Auto Scaling groups found', function (done) {
            const cache = createNullCache();
            webTierAsgCloudWatchLogs.run(cache, { web_tier_tag_key: 'web_tier' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        }); 

    });
});