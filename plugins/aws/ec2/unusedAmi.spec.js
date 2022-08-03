var expect = require('chai').expect;
const unusedAmi = require('./unusedAmi');

const describeImages = [
    {
        "Architecture": "x86_64",
        "CreationDate": "2020-10-14T22:59:03.000Z",
        "ImageId": "ami-026c295331eb10e50",
        "ImageLocation": "111122223333/test-32",
        "ImageType": "machine",
        "Public": false,
        "OwnerId": "111122223333",
        "PlatformDetails": "Linux/UNIX",
        "State": "available",
        "Name": "test-32"
    },
    {
        "Architecture": "x86_64",
        "CreationDate": "2020-10-14T22:59:03.000Z",
        "ImageId": "ami-00000000000000000",
        "ImageLocation": "111122223333/test-32",
        "ImageType": "machine",
        "Public": false,
        "OwnerId": "111122223333",
        "PlatformDetails": "Linux/UNIX",
        "UsageOperation": "RunInstances",
        "State": "available",
        "Name": "test-32"
    }
];

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-026c295331eb10e50",
                "InstanceId": "i-023c9bc2aed01cc5e",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-09ff2e14445b8c226"
                    }
                ]
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    }
];

const describeLaunchConfigurations = [
    {
        "LaunchConfigurationName": "test-32",
        "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:111122223333:launchConfiguration:79298288-6ac0-4031-bf3c-05aa13c64bbc:launchConfigurationName/test-32",
        "ImageId": "ami-026c295331eb10e50",
        "KeyName": "auto-scaling-test-instance",
        "SecurityGroups": [
            "sg-099a21ef57db4bad1"
        ],
        "ClassicLinkVPCSecurityGroups": [],
        "UserData": "",
        "InstanceType": "t2.micro",
        "KernelId": "",
        "RamdiskId": "",
        "BlockDeviceMappings": [],
        "InstanceMonitoring": {
            "Enabled": false
        },
        "IamInstanceProfile": "arn:aws:iam::111122223333:instance-profile/EMR_EC2_DefaultRole",
        "CreatedTime": "2020-10-14T23:22:41.431Z",
        "EbsOptimized": false
    },
];

const describeLaunchTemplates = [
    {
        "LaunchTemplateId": "lt-0219ac0443364d22d",
        "LaunchTemplateName": "Test-lt",
        "CreateTime": "2021-07-19T12:32:41.000Z",
        "CreatedBy": "arn:aws:iam::111111111111:user/user",
        "DefaultVersionNumber": 4,
        "LatestVersionNumber": 4,
        "Tags": []
    }
]

const describeLaunchTemplateVersions = [
    {
        "LaunchTemplateVersions": [
          {
            "LaunchTemplateId": "lt-0219ac0443364d22d",
            "LaunchTemplateName": "Test-lt",
            "VersionNumber": 4,
            "CreateTime": "2021-07-19T13:58:15.000Z",
            "CreatedBy": "arn:aws:iam::111111111111:user/user",
            "DefaultVersion": true,
            "LaunchTemplateData": {
                "EbsOptimized": false,
                "BlockDeviceMappings": [],
                "NetworkInterfaces": [],
                "ImageId": "ami-026c295331eb10e50",
                "InstanceType": "t1.micro",
                "KeyName": "user-kp",
                "TagSpecifications": [],
                "ElasticGpuSpecifications": [],
                "ElasticInferenceAccelerators": [],
                "SecurityGroupIds": [
                    "sg-043778823f73431a7",
                    "sg-02e2c70cd463dca29"
                ],
                "SecurityGroups": [],
                "LicenseSpecifications": []
            }
          },
        ]
    },
]

const createCache = (images, instances, launchConfig, launchTemplate, launchTemplateVersion) => {
    return {
        ec2:{
            describeImages: {
                'us-east-1': {
                    data: images
                },
            },
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
            describeLaunchTemplates: {
                'us-east-1': {
                    data: launchTemplate
                },
            },
            describeLaunchTemplateVersions: {
                'us-east-1': {
                    "lt-0219ac0443364d22d": {
                        data: launchTemplateVersion
                    }
                },
            },
        },
        autoscaling:{
            describeLaunchConfigurations: {
                'us-east-1': {
                    data: launchConfig
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeImages: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 AMIs'
                    },
                },
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 instances'
                    },
                },
            },
            describeLaunchTemplates: {
                'us-east-1': {
                    err: {
                        message: 'error describing launch templates'
                    }
                },
            },
            describeLaunchTemplateVersions: {
                'us-east-1': {
                    err: {
                        message: 'error describing launch template versions'
                    }
                },
            },
        },
        autoscaling: {
            describeLaunchConfigurations:{
                'us-east-1': {
                    err: {
                        message: 'error describing Auto Scaling launch configurations'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': null,
            },
            describeInstances: {
                'us-east-1': null,
            },
            describeLaunchTemplates: {
                'us-east-1': null,
            },
            describeLaunchTemplateVersions: {
                'us-east-1': null,
            },
        },
        autoscaling: {
            describeLaunchConfigurations:{
                'us-east-1': null,
            },
        },
    };
};

describe('unusedAmi', function () {
    describe('run', function () {
        it('should PASS if Amazon Machine Image is in use', function (done) {
            const cache = createCache([describeImages[0]], [describeInstances[0]], describeLaunchConfigurations[0], [describeLaunchTemplates[0]], describeLaunchTemplateVersions[0]);
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if Amazon Machine Image is used by launch template', function (done) {
            const cache = createCache([describeImages[0]], [], [], [describeLaunchTemplates[0]], describeLaunchTemplateVersions[0]);
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if Amazon Machine Image is not in use', function (done) {
            const cache = createCache([describeImages[1]], [describeInstances[0]], describeLaunchConfigurations[0], [describeLaunchTemplates[0]], describeLaunchTemplateVersions[0]);
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if Amazon Machine Image is not in use ', function (done) {
            const cache = createCache([describeImages[1]], [], [], []);
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no Amazon Machine Images found', function (done) {
            const cache = createCache([]);
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe images', function (done) {
            const cache = createErrorCache();
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe images response not found', function (done) {
            const cache = createNullCache();
            unusedAmi.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
