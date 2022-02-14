var expect = require('chai').expect;
const asgUnusedLaunchConfiguration = require('./asgUnusedLaunchConfiguration');

const describeAutoScalingGroups = [
    {
        "AutoScalingGroupName": "sadeed-grp1",
        "AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:000111222333:autoScalingGroup:1efc7b66-fbd4-4a5b-8086-8b95b0b74603:autoScalingGroupName/sadeed-grp1",
        "LaunchConfigurationName": "mine2",
        "MinSize": 1,
        "MaxSize": 5,
        "DesiredCapacity": 1,
        "DefaultCooldown": 300,
        "AvailabilityZones": [
            "us-east-1a",
            "us-east-1b"
        ],
        "LoadBalancerNames": [],
        "TargetGroupARNs": [],
        "HealthCheckType": "EC2",
        "HealthCheckGracePeriod": 300,
        "Instances": [],
        "CreatedTime": "2022-01-18T09:39:04.243000+00:00",
        "SuspendedProcesses": [],
        "VPCZoneIdentifier": "subnet-02ed4181800d4658b,subnet-06629b4200870c740",
        "EnabledMetrics": [],
        "Tags": [],
        "TerminationPolicies": [
            "Default"
        ],
        "NewInstancesProtectedFromScaleIn": false,
        "ServiceLinkedRoleARN": "arn:aws:iam::000011112222:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    }
];

const describeLaunchConfigurations = [
    {
        "LaunchConfigurationName": "mine2",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:000011112222:launchConfiguration:8fceeaaa-c984-4cad-a20d-3e09eaea2440:launchConfigurationName/mine2",
        "ImageId": "ami-085b20a79fc1af8f5",
        "KeyName": "test",
        "SecurityGroups": [
            "sg-008a9126e4f284b6c"
        ],
        "ClassicLinkVPCSecurityGroups": [],
        "UserData": "",
        "InstanceType": "a1.medium",
        "KernelId": "",
        "RamdiskId": "",
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/sdj",
                "Ebs": {
                    "VolumeSize": 5,
                    "VolumeType": "gp2",
                    "DeleteOnTermination": false,
                    "Encrypted": true
                }
            },
        ],
        "InstanceMonitoring": {
            "Enabled": false
        },
        "CreatedTime": "2022-01-18T09:38:17.445000+00:00",
        "EbsOptimized": false
    },
    {
        "LaunchConfigurationName": "mine3",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:000011112222:launchConfiguration:917c072a-383b-48b6-9675-ed0e1f4e6f51:launchConfigurationName/mine3",
        "ImageId": "ami-085b20a79fc1af8f5",
        "KeyName": "test",
        "SecurityGroups": [
            "sg-0d55142f499300efb"
        ],
        "ClassicLinkVPCSecurityGroups": [],
        "UserData": "",
        "InstanceType": "a1.medium",
        "KernelId": "",
        "RamdiskId": "",
        "BlockDeviceMappings": [
            {
                "DeviceName": "/dev/sdj",
                "Ebs": {
                    "VolumeSize": 5,
                    "VolumeType": "gp2",
                    "DeleteOnTermination": false,
                    "Encrypted": true
                }
            },
        ],
        "InstanceMonitoring": {
            "Enabled": false
        },
        "CreatedTime": "2022-01-18T10:27:56.426000+00:00",
        "EbsOptimized": false
    }
];

const createCache = (group, config) => {
    return {
        autoscaling:{
            describeAutoScalingGroups: {
                'us-east-1': {
                    data: group
                },
            },
            describeLaunchConfigurations: {
                'us-east-1': {
                    data: config
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        autoscaling:{
            describeAutoScalingGroups: {
                'us-east-1': {
                    err: {
                        message: 'error while describing ElastiCache clusters'
                    },
                },
            },
            describeLaunchConfigurations: {
                'us-east-1': {
                    err: {
                        message: 'error while describing ElastiCache reserved cache nodes'
                    },
                },
            },
        },
    };
};


describe('asgUnusedLaunchConfiguration', function () {
    describe('run', function () {
        it('should PASS if Auto Scaling launch configuration is being used', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], [describeLaunchConfigurations[0]]);
            asgUnusedLaunchConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is being used');
                done();
            });
        });

        it('should FAIL if Auto Scaling launch configuration is not being used', function (done) {
            const cache = createCache([describeAutoScalingGroups[0]], [describeLaunchConfigurations[1]]);
        asgUnusedLaunchConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not being used');
                done();
            });
        });

        it('should PASS if no Auto Scaling launch configurations found', function (done) {
            const cache = createCache([], []);
            asgUnusedLaunchConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Auto Scaling launch configurations found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Auto Scaling launch configurations', function (done) {
            const cache = createErrorCache([],null);
            asgUnusedLaunchConfiguration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Auto Scaling launch configurations');
                done();
            });
        });
    });
});