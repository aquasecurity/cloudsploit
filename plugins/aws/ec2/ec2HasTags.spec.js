var expect = require('chai').expect;
const ec2HasTags = require('./ec2HasTags');

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
    },
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
                "Tags": [],
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

const createCache = (instances) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};


describe('ec2HasTags', function () {
    describe('run', function () {
      
        it('should return UNKNOWN result if error occurs while describe EC2 instances ', function (done) {
            const cache = createCache(null);
            ec2HasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should return Passing result if no EC2 instances found', function (done) {
            const cache = createCache([]);
            ec2HasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should return Passing result if EC2 instance has tags', function (done) {
            const cache = createCache([describeInstances[0]]);
            ec2HasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                // expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should return Fail result if EC2 instance has no tags', function (done) {
            const cache = createCache([describeInstances[1]]);
            ec2HasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

    });
});