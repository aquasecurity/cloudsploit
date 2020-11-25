var expect = require('chai').expect;
const publicIpAddress = require('./publicIpAddress');

const describeInstances = [ 
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-023c9bc2aed01cc5e",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-10-13T23:01:41.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                "PrivateIpAddress": "172.31.87.231",
                "ProductCodes": [],
                "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                "PublicIpAddress": "54.204.209.252",
                "State": {
                    "Code": 16,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-10-13T23:01:42.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-0e107fa5b4a3bcd41"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "NetworkInterfaces": [
                    {
                        "Association": {
                            "IpOwnerId": "amazon",
                            "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                            "PublicIp": "54.204.209.252"
                        },
                        "Attachment": {
                            "AttachTime": "2020-10-13T23:01:41.000Z",
                            "AttachmentId": "eni-attach-02616f8aaab876e7d",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-09ff2e14445b8c226"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "12:19:c4:d5:29:83",
                        "NetworkInterfaceId": "eni-0ccc43812db0f2b76",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                        "PrivateIpAddress": "172.31.87.231",
                        "PrivateIpAddresses": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                                    "PublicIp": "54.204.209.252"
                                },
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                                "PrivateIpAddress": "172.31.87.231"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-09ff2e14445b8c226"
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
                    "HttpEndpoint": "enabled"
                }
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-023c9bc2aed01cc5e",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-10-13T23:01:41.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                "PrivateIpAddress": "172.31.87.231",
                "ProductCodes": [],
                "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                "PublicIpAddress": "",
                "State": {
                    "Code": 16,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "AttachTime": "2020-10-13T23:01:42.000Z",
                            "DeleteOnTermination": true,
                            "Status": "attached",
                            "VolumeId": "vol-0e107fa5b4a3bcd41"
                        }
                    }
                ],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "NetworkInterfaces": [
                    {
                        "Association": {
                            "IpOwnerId": "amazon",
                            "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                            "PublicIp": "54.204.209.252"
                        },
                        "Attachment": {
                            "AttachTime": "2020-10-13T23:01:41.000Z",
                            "AttachmentId": "eni-attach-02616f8aaab876e7d",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attached"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-09ff2e14445b8c226"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "12:19:c4:d5:29:83",
                        "NetworkInterfaceId": "eni-0ccc43812db0f2b76",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                        "PrivateIpAddress": "172.31.87.231",
                        "PrivateIpAddresses": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                                    "PublicIp": "54.204.209.252"
                                },
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-87-231.ec2.internal",
                                "PrivateIpAddress": "172.31.87.231"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-09ff2e14445b8c226"
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
                    "HttpEndpoint": "enabled"
                }
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
    {
        "Groups": [],
        "Instances": [],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
];

const createCache = (instances) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
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
                        message: 'error describing EC2 instances'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': null,
            }
        },
    };
};

describe('publicIpAddress', function () {
    describe('run', function () {
        it('should PASS if EC2 instance does not have public IP address attached', function (done) {
            const cache = createCache([describeInstances[1]]);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EC2 instance has public IP address attached', function (done) {
            const cache = createCache([describeInstances[0]]);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no EC2 instances found', function (done) {
            const cache = createCache([]);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if EC2 instance description is not found', function (done) {
            const cache = createCache([describeInstances[2]]);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe EC2 instances', function (done) {
            const cache = createErrorCache();
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe instances response is not found', function (done) {
            const cache = createNullCache();
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});