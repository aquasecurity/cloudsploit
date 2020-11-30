var expect = require('chai').expect;
const openAllPortsProtocols = require('./openAllPortsProtocols');

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [
            {
                "IpProtocol": "-1",
                "IpRanges": [],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-aa941691",
                        "UserId": "111122223333"
                    }
                ]
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
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
    },
    {
        "Description": "Allows SSh access to developer",
        "GroupName": "spec-test-sg",
        "IpPermissions": [{
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
            "UserIdGroupPairs": []
        }],
        "OwnerId": "12345654321",
        "GroupId": "sg-0b5f2771716acfee4",
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
    }
];

const createCache = (groups) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    data: groups
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
            }
        },
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('openAllPortsProtocols', function () {
    describe('run', function () {
        it('should PASS if no open ports found', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if security group has all ports open to 0.0.0.0/0 and all ports open to ::/0', function (done) {
            const cache = createCache([describeSecurityGroups[1]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createErrorCache();
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
