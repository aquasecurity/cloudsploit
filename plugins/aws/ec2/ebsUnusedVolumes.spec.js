var expect = require('chai').expect;
const ebsUnusedVolumes = require('./ebsUnusedVolumes');

describeInstances = [
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-02354e95b39ca8dec",
                "InstanceId": "i-03afb9daa31f31bb0",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-08-31T23:52:43.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1e",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                "PrivateIpAddress": "172.31.54.187",
                "ProductCodes": [],
                "PublicDnsName": "",
                "State": {
                    "Code": 80,
                    "Name": "stopped"
                },
                "StateTransitionReason": "User initiated (2020-09-01 03:39:08 GMT)",
                "SubnetId": "subnet-6a8b635b",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-08-25T02:21:49.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-025b523c155020b10"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "IamInstanceProfile": {
                    "Arn": "arn:aws:iam::111122223333:instance-profile/AmazonSSMRoleForInstancesQuickSetup",
                    "Id": "AIPAYE32SRU53G7VOI2UM"
                },
                "NetworkInterfaces": [
                    {
                        "Attachment": {
                            "AttachTime": "2020-08-25T02:21:48.000Z",
                            "AttachmentId": "eni-attach-077c0f4c969c20b4c",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-4",
                                "GroupId": "sg-0174d5e394e23015e"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "06:22:7f:a4:48:f3",
                        "NetworkInterfaceId": "eni-0a53de7b449ed51e0",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                        "PrivateIpAddress": "172.31.54.187",
                        "PrivateIpAddresses": [
                            {
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-54-187.ec2.internal",
                                "PrivateIpAddress": "172.31.54.187"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-6a8b635b",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-4",
                        "GroupId": "sg-0174d5e394e23015e"
                    }
                ],
                "SourceDestCheck": true,
                "StateReason": {
                    "Code": "Client.UserInitiatedShutdown",
                    "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
                },
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": "sploit-959-test-instance"
                    }
                ],
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
                    "HttpEndpoint": "enabled"
                }
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-073e1215b28407ada"
    }
]

describeVolumes = [
    {
        "Attachments": [],
        "AvailabilityZone": "us-east-1d",
        "CreateTime": "2020-09-01T03:40:13.595Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "available",
        "VolumeId": "vol-0d7619e666a54b52a",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    },
    {
        "Attachments": [
            {
                "AttachTime": "2020-08-25T02:21:49.000Z",
                "Device": "/dev/xvda",
                "InstanceId": "i-03afb9daa31f31bb0",
                "State": "attached",
                "VolumeId": "vol-025b523c155020b10",
                "DeleteOnTermination": true
            }
        ],
        "AvailabilityZone": "us-east-1e",
        "CreateTime": "2020-08-25T02:21:49.073Z",
        "Encrypted": false,
        "Size": 8,
        "SnapshotId": "snap-06d919bfeced8496a",
        "State": "in-use",
        "VolumeId": "vol-025b523c155020b10",
        "Iops": 100,
        "VolumeType": "gp2",
        "MultiAttachEnabled": false
    }
]

const createCache = (instances, volumes) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
            describeVolumes: {
                'us-east-1': {
                    data: volumes
                }
            }
        },
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
                },
            },
            describeVolumes: {
                'us-east-1': {
                    err: {
                        message: 'error describing ebs volumes'
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
            describeVolumes: {
                'us-east-1': null,
            },
        },
    };
};

describe('ebsUnusedVolumes', function () {
    describe('run', function () {
        it('should PASS if EBS volume is attached to EC2 instance', function (done) {
            const cache = createCache([describeInstances[0]], [describeVolumes[1]]);
            ebsUnusedVolumes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EBS volume is not attached to EC2 instance', function (done) {
            const cache = createCache([describeInstances[0]], [describeVolumes[0]]);
            ebsUnusedVolumes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if no EBS volumes found', function (done) {
            const cache = createCache([describeInstances[0]],[]);
            ebsUnusedVolumes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to fetch EC2 instances or EBS volumes', function (done) {
            const cache = createNullCache();
            ebsUnusedVolumes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error occurs while describe EC2 instances or EBS volumes', function (done) {
            const cache = createErrorCache();
            ebsUnusedVolumes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});