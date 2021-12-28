var expect = require('chai').expect;
const ssmManagedInstances = require('./ssmManagedInstances');

const describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0ed9277fb7eb570c9",
                "InstanceId": "i-0ccdd1122ddccdd",
                "InstanceType": "t2.micro",
                "KeyName": "test",
                "LaunchTime": "2021-12-19T19:49:14+00:00",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1a",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-91-212.ec2.internal",
                "PrivateIpAddress": "172.31.91.212",
                "ProductCodes": [],
                "PublicDnsName": "ec2-54-89-182-216.compute-1.amazonaws.com",
                "PublicIpAddress": "54.89.182.216",
                "State": {
                    "Code": 16,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-02ed4181800d4658b",
                "VpcId": "vpc-0f4f4575a74fac014",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2021-12-19T19:49:15+00:00",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-0ebea24b6b5ab89d5"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111222333444:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPARPGOCGXS55MJYEHU6"
                },
                "NetworkInterfaces": [
                    {
                        "Association": {
                            "IpOwnerId": "amazon",
                            "PublicDnsName": "ec2-54-89-182-216.compute-1.amazonaws.com",
                            "PublicIp": "54.89.182.216"
                        },
                        "Attachment": {
                            "AttachTime": "2021-12-19T19:49:14+00:00",
                            "AttachmentId": "eni-attach-0f5bb44c6fbee9f02",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached",
                            "NetworkCardIndex": 0
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-06866e2098b1cf826"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "12:69:df:6f:57:67",
                        "NetworkInterfaceId": "eni-0686b6b3e47bdc6c9",
                        "OwnerId": "111222333444",
                        "PrivateDnsName": "ip-172-31-91-212.ec2.internal",
                        "PrivateIpAddress": "172.31.91.212",
                        "PrivateIpAddresses": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-54-89-182-216.compute-1.amazonaws.com",
                                    "PublicIp": "54.89.182.216"
                                },
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-91-212.ec2.internal",
                                "PrivateIpAddress": "172.31.91.212"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-02ed4181800d4658b",
                        "VpcId": "vpc-0f4f4575a74fac014",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-06866e2098b1cf826"
                    }
                ],
                "SourceDestCheck": true,
                "VirtualizationType": "hvm",
                "CpuOptions": {
                    "CoreCount": 1,
                    "ThreadsPerCore": 1
                },
                "CapacityReservationSpecification": {
                    "CapacityReservationPreference": "open"
                },
                "HibernationOptions": {
                    "Configured": false
                },
                "MetadataOptions": {
                    "State": "applied",
                    "HttpTokens": "optional",
                    "HttpPutResponseHopLimit": 1,
                    "HttpEndpoint": "enabled",
                    "HttpProtocolIpv6": "disabled"
                },
                "EnclaveOptions": {
                    "Enabled": false
                },
                "PlatformDetails": "Linux/UNIX",
                "UsageOperation": "RunInstances",
                "UsageOperationUpdateTime": "2021-12-19T19:49:14+00:00"
            }
        ],
        "OwnerId": "111222333444",
        "ReservationId": "r-07a34e57731d9d38c"
    }
];

const describeInstanceInformation = [
    {
        "InstanceId": "i-0ccdd1122ddccdd",
        "PingStatus": "Online",
        "LastPingDateTime": "2021-12-19T15:20:09.764000-08:00",
        "AgentVersion": "3.1.715.0",
        "IsLatestVersion": true,
        "PlatformType": "Linux",
        "PlatformName": "Amazon Linux",
        "PlatformVersion": "2",
        "ResourceType": "EC2Instance",
        "IPAddress": "172.31.91.212",
        "ComputerName": "ip-172-31-91-212.ec2.internal",
        "AssociationStatus": "Success",
        "LastAssociationExecutionDate": "2021-12-19T15:17:22.848000-08:00",
        "LastSuccessfulAssociationExecutionDate": "2021-12-19T15:17:22.848000-08:00",
        "AssociationOverview": {
            "DetailedStatus": "Success",
            "InstanceAssociationStatusAggregatedCount": {
                "Success": 4
            }
        }
    }
];



const createCache = (instances, instanceInfo) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: instances
                }
            }
        },
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: instanceInfo
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing ec2 instances'
                    },
                }
            }
        },
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    err: {
                        message: 'error describing instance information'
                    },
                }
            }
        }
    };
};

describe('ssmManagedInstances', function () {
    describe('run', function () {
        it('should PASS if there are no ec2 Instance reservations', function (done) {
            const cache = createCache([], describeInstanceInformation);
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no ec2 instances', function (done) {
            const cache = createCache([], []);
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });


        it('should PASS if EC2 instance is being managed by AWS SSM', function (done) {
            const cache = createCache(describeInstances, describeInstanceInformation);
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if there are ec2 instances and ssmManagedInstances but ec2 instance is not managed by SSM', function (done) {
            const cache = createCache([
                {
                    Instances: [
                        {
                            InstanceId: 'i-abc1234'
                        }
                    ]
                }
            ], describeInstanceInformation);
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if error while fetching ec2 instances', function (done) {
            const cache = createErrorCache();
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if error while fetching ssm instance information', function (done) {
            const cache = createErrorCache();
            ssmManagedInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});
