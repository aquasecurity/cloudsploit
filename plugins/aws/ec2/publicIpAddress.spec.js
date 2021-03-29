var expect = require('chai').expect;
const publicIpAddress = require('./publicIpAddress');

const describeInstances = [ 
    {
        "Groups": [],
        "Instances": [
            {
                "AmiLaunchIndex": 0,
                "PublicDnsName": "ec2-54-204-209-252.compute-1.amazonaws.com",
                "PublicIpAddress": "54.204.209.252",
                "NetworkInterfaces": [
                    {
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-08dd2e14445b8c801"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "SourceDestCheck": true,
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-08dd2e14445b8c801"
                    }
                ]
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
    {
        "Instances": [
            {
                "NetworkInterfaces": [
                    {
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-09ff2e14445b8c226"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
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
    },
    {
        "Groups": [],
        "Instances": [],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
    {
        "Instances": [
            {
                "NetworkInterfaces": [
                    {
                        "Groups": [
                            {
                                "GroupName": "launch-wizard-1",
                                "GroupId": "sg-08dd2e14445b8c801"
                            }
                        ],
                        "Ipv6Addresses": [],
                        "Status": "in-use",
                        "SubnetId": "subnet-673a9a46",
                        "VpcId": "vpc-99de2fe4",
                        "InterfaceType": "interface"
                    }
                ],
                "SecurityGroups": [
                    {
                        "GroupName": "launch-wizard-1",
                        "GroupId": "sg-08dd2e14445b8c801"
                    }
                ]
            }
        ],
        "OwnerId": "111122223333",
        "ReservationId": "r-0c8617b20269c4de0"
    },
];

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "launch-wizard-2",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                      "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
            },
        ],
        "OwnerId": "560213429563",
        "GroupId": "sg-08dd2e14445b8c801",
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "default VPC security group",
        "GroupName": "sg-09ff2e14445b8c226",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
            },
        ],
        "OwnerId": "560213429563",
        "GroupId": "sg-aa941691",
        "VpcId": "vpc-99de2fe4"
    }
];

const createCache = (instances, sgs) => {
    return {
        ec2:{
            describeInstances: {
                'us-east-1': {
                    data: instances
                },
            },
            describeSecurityGroups: {
                'us-east-1': {
                    data: sgs
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
            const cache = createCache([describeInstances[1]], describeSecurityGroups);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if EC2 instance has public IP address attached but attached security group is not open to public', function (done) {
            const cache = createCache([describeInstances[3]], describeSecurityGroups);
            publicIpAddress.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if EC2 instance has public IP address attached', function (done) {
            const cache = createCache([describeInstances[0]], describeSecurityGroups);
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
            const cache = createCache([describeInstances[2]], describeSecurityGroups);
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