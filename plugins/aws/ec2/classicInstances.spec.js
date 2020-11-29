var expect = require('chai').expect;
const classicInstances = require('./classicInstances');

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0ceecc81a1c5829f6",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-09T21:27:25.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PublicIpAddress": "3.84.159.125",
                "State": {
                    "Code": 0,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
                "NetworkInterfaces": [
                    {
                        "Association": {
                            "IpOwnerId": "amazon",
                            "PublicDnsName": "ec2-3-84-159-125.compute-1.amazonaws.com",
                            "PublicIp": "3.84.159.125"
                        },
                        "Attachment": {
                            "AttachTime": "2020-11-09T21:27:25.000Z",
                            "AttachmentId": "eni-attach-0ac6a634b2341fcbf",
                            "DeleteOnTermination": true,
                            "DeviceIndex": 0,
                            "Status": "attaching"
                        },
                        "Description": "",
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-3",
                                "GroupId": "sg-00227d48f69020516"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "MacAddress": "12:b5:1d:12:ba:01",
                        "NetworkInterfaceId": "eni-060ab6c65e9b16de9",
                        "OwnerId": "111122223333",
                        "PrivateDnsName": "ip-172-31-83-241.ec2.internal",
                        "PrivateIpAddress": "172.31.83.241",
                        "PrivateIpAddresses": [
                            {
                                "Association": {
                                    "IpOwnerId": "amazon",
                                    "PublicDnsName": "ec2-3-84-159-125.compute-1.amazonaws.com",
                                    "PublicIp": "3.84.159.125"
                                },
                                "Primary": true,
                                "PrivateDnsName": "ip-172-31-83-241.ec2.internal",
                                "PrivateIpAddress": "172.31.83.241"
                            }
                        ],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
            }
        ]
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0ceecc81a1c5829f6",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-09T21:27:25.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PublicIpAddress": "3.84.159.125",
                "State": {
                    "Code": 0,
                    "Name": "running"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
            }
        ]
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0ceecc81a1c5829f6",
                "InstanceType": "t2.micro",
                "KeyName": "auto-scaling-test-instance",
                "LaunchTime": "2020-11-09T21:27:25.000Z",
                "Monitoring": {
                    "State": "disabled"
                },
                "Placement": {
                    "AvailabilityZone": "us-east-1b",
                    "GroupName": "",
                    "Tenancy": "default"
                },
                "PublicIpAddress": "3.84.159.125",
                "State": {
                    "Code": 0,
                    "Name": "pending"
                },
                "StateTransitionReason": "",
                "SubnetId": "subnet-673a9a46",
                "VpcId": "vpc-99de2fe4",
                "Architecture": "x86_64",
                "BlockDeviceMappings": [],
                "ClientToken": "",
                "EbsOptimized": false,
                "EnaSupport": true,
                "Hypervisor": "xen",
            }
        ]
    }
];


const createCache = (instances) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing EC2 instances'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};

describe('classicInstances', function () {
    describe('run', function () {
        it('should PASS if EC2 instances are in a VPC', function (done) {
            const cache = createCache([describeInstances[0]]);
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if EC2 instances are in EC2-Classic', function (done) {
            const cache = createCache([describeInstances[1]]);
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache([]);
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no running instances found', function (done) {
            const cache = createCache([describeInstances[2]]);
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe instances', function (done) {
            const cache = createErrorCache();
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe instances response not found', function (done) {
            const cache = createNullCache();
            classicInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
