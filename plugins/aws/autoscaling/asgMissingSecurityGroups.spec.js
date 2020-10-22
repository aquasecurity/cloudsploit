var expect = require('chai').expect;
const asgMissingSecurityGroups = require('./asgMissingSecurityGroups');

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
            "sg-06cccc47e5b3e1ee9",
            "sg-06cccccccccceaaaa",
            "sg-06ccccccbbbbbbbbb"
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
        "LaunchConfigurationName": "test-lc-44",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:f20acca0-07b4-4cec-9174-75547b193446:launchConfigurationName/test-lc-44",
        "ImageId": "ami-02354e95b39ca8dec",
        "KeyName": "auto-scaling-test-instance",
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
    }
]

const describeSecurityGroups = [
    {
        "Description": "launch-wizard-4 created 2020-08-25T07:21:35.823+05:00",
        "GroupName": "launch-wizard-4",
        "IpPermissions": [
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-06cccc47e5b3e1ee9",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    }
]


const createCache = (configs, groups) => {
    return {
        autoscaling: {
            describeLaunchConfigurations: {
                'us-east-1': {
                    err: null,
                    data: configs
                },
            },
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: null,
                    data: groups
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        autoscaling: {
            describeLaunchConfigurations: {
                'us-east-1': {
                    err: {
                        message: 'error describing Auto Scaling launch configurations'
                    },
                },
            },
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 security groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        autoscaling: {
            describeLaunchConfigurations: {
                'us-east-1': null,
            },
        },
        ec2: {
            describeSecurityGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('asgMissingSecurityGroups', function () {
    describe('run', function () {
        it('should PASS if Auto Scaling launch configuration does not reference any missing EC2 security group', function (done) {
            const cache = createCache([describeLaunchConfigurations[0]], [describeSecurityGroups[0]]);
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if Auto Scaling launch configuration references missing EC2 security group(s)', function (done) {
            const cache = createCache([describeLaunchConfigurations[1]], [describeSecurityGroups[0]]);
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Auto Scaling launch configurations found', function (done) {
            const cache = createCache([]);
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if Auto Scaling launch configuration does not have any security groups associated', function (done) {
            const cache = createCache([describeLaunchConfigurations[2]], [describeSecurityGroups[0]]);
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no EC2 security groups found', function (done) {
            const cache = createCache([describeLaunchConfigurations[1]],[]);
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe Auto Scaling launch configurations', function (done) {
            const cache = createErrorCache();
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe Auto Scaling launch configurations response not found', function (done) {
            const cache = createNullCache();
            asgMissingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
