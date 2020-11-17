var expect = require('chai').expect;
const overlappingSecurityGroups = require('./overlappingSecurityGroups');

const describeInstances = [
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
        ],
    },
    {
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462547",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462548",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462549",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462550",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462551",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462552",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462553",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462554",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462555",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462556",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462557",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462558",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462559",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462560",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462561",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462562",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462563",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462564",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462565",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462566",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
            {
                "AmiLaunchIndex": 0,
                "ImageId": "ami-0947d2ba12ee1ff75",
                "InstanceId": "i-0e5b41e1d67462567",
                "InstanceType": "t2.micro",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941691"
                    },
                    {
                        "GroupName": "default",
                        "GroupId": "sg-aa941692"
                    }
                ],
            },
        ],
    },
];

const describeSecurityGroups = [
    {
        "Description": "Allows SSh access to developer",
        "GroupName": "spec-test-sg",
        "IpPermissions": [{
            "FromPort": 25,
            "IpProtocol": "tcp",
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0"
                }
            ],
            "Ipv6Ranges": [
                {
                    "CidrIpv6": "::/0"
                }
            ],
            "PrefixListIds": [],
            "ToPort": 30,
            "UserIdGroupPairs": [{
                GroupId: 'sg-0b5f2771716acfee4',
                GroupName: 'spec-test-sg'
              }]
        }],
        "OwnerId": "12345654321",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [
            {
                "FromPort": 25,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [
                    {
                        "CidrIpv6": "::/0"
                    }
                ],
                "PrefixListIds": [],
                "ToPort": 25,
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Allows SSh access to developer",
        "GroupName": "spec-test-sg",
        "IpPermissions": [{
            "FromPort": 25,
            "IpProtocol": "tcp",
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0"
                }
            ],
            "Ipv6Ranges": [
                {
                    "CidrIpv6": "::/0"
                }
            ],
            "PrefixListIds": [],
            "ToPort": 30,
            "UserIdGroupPairs": [{
                GroupId: 'sg-0b5f2771716acfee4',
                GroupName: 'spec-test-sg'
              }]
        }],
        "OwnerId": "12345654321",
        "GroupId": "sg-aa941692",
        "IpPermissionsEgress": [
            {
                "FromPort": 25,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [
                    {
                        "CidrIpv6": "::/0"
                    }
                ],
                "PrefixListIds": [],
                "ToPort": 25,
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
];

const createCache = (groups, instances) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    data: groups
                },
            },
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
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': null,
            },
            describeInstances: {
                'us-east-1': null,
            },
        },
    };
};


describe('overlappingSecurityGroups', function () {
    describe('run', function () {
        it('should PASS if no overlapping instance security groups found', function (done) {
            const cache = createCache([describeSecurityGroups[0]], [describeInstances[0]]);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if instance has overlapping security group rules via groups', function (done) {
            const cache = createCache(describeSecurityGroups, [describeInstances[0]]);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should WARN if more than 20 instances have overlapping security groups', function (done) {
            const cache = createCache(describeSecurityGroups, describeInstances);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no instances found', function (done) {
            const cache = createCache(describeSecurityGroups, []);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe security groups', function (done) {
            const cache = createErrorCache();
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to describe instances', function (done) {
            const cache = createCache(describeSecurityGroups);
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            overlappingSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
        
    });
});
