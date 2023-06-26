var expect = require('chai').expect;
const ec2PublicSubnet = require('./ec2PublicSubnet');

const describeInstances = [
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
                "SubnetId": "subnet-6a8b636a",
                "VpcId": "vpc-0af5156c",
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
                        "SubnetId": "subnet-6a8b636a",
                        "VpcId": "vpc-0af5156c",
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

const describeRouteTables = [
    {
        "Associations": [
          {
            "Main": false,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "SubnetId":"subnet-6a8b636a",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
          {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active"
          },
          {
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-sedwednkq",
            "Origin": "CreateRouteTable",
            "State": "active"
        }
        ],
        "Tags": [],
        "VpcId": "vpc-0af5156c",
        "OwnerId": "000011112222"
    },
    {
        "Associations": [
          {
            "Main": false,
            "RouteTableAssociationId": "rtbassoc-79c7a000",
            "RouteTableId": "rtb-f6522690",
            "SubnetId":"subnet-6a8b635b",
            "AssociationState": {
              "State": "associated"
            }
          }
        ],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-f6522690",
        "Routes": [
            {
                "DestinationCidrBlock": "172.31.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            },
            
        ],
        "Tags": [],
        "VpcId": "vpc-0af515f7",
        "OwnerId": "000011112222"
    }
];

const createCache = (instance, routeTables) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: instance
                },
            },
            describeRouteTables: {
                'us-east-1': {
                    data: routeTables
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
                        message: 'error describing ec2 instance'
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
        },
    };
};


describe('ec2PublicSubnet', function () {
    describe('run', function () {
        it('should PASS if EC2 instance is not deployed on a public subnet', function (done) {
            const cache = createCache([describeInstances[0]], describeRouteTables);
            ec2PublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EC2 instance is not deployed on public subnet');
                done();
            });
        });

        // it('should FAIL if EC2 instance is deployed on a public subnet', function (done) {
        //     const cache = createCache([describeInstances[1]], describeRouteTables);
        //     ec2PublicSubnet.run(cache, {}, (err, results) => {
        //         expect(results.length).to.equal(1);
        //         expect(results[0].status).to.equal(2);
        //         expect(results[0].region).to.equal('us-east-1');
        //         expect(results[0].message).to.include('EC2 instance is deployed on public subnet');
        //         done();
        //     });
        // });

         it('should PASS if no EC2 instance found', function (done) {
            const cache = createCache([]);
            ec2PublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No EC2 instances found');
                done();
            });
        });

         it('should UNKNOWN if there unable to query for EC2 instance', function (done) {
            const cache = createErrorCache();
            ec2PublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for instances: ');
                done();
            });
        });

        it('should not return any results describe EC2 instance response not found', function (done) {
            const cache = createNullCache();
            ec2PublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there unable to query for RouteTables', function (done) {
            const cache = createCache([describeInstances[1]]);
            ec2PublicSubnet.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for RouteTables: ');
                done();
            });
        });
    });
});
