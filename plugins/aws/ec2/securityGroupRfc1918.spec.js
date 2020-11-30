var expect = require('chai').expect;
const securityGroupRfc1918 = require('./securityGroupRfc1918');

const describeSecurityGroups = [
    {
        "Description": "launch-wizard-4 created 2020-08-25T07:21:35.823+05:00",
        "GroupName": "launch-wizard-4",
        "IpPermissions": [
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    },
                    {
                        "CidrIp": "10.0.0.0/8"
                    },
                    {
                        "CidrIp": "172.16.0.0/12"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-0174d5e394e23015e",
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
        "Description": "launch-wizard-3 created 2020-08-22T00:48:22.981+05:00",
        "GroupName": "launch-wizard-3",
        "IpPermissions": [
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-047e6cc36b13ec60e",
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
        "Description": "launch-wizard-3 created 2020-08-22T00:48:22.981+05:00",
        "GroupName": "launch-wizard-3",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-047e6cc36b13ec60e",
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
    }
]

const createCache = (securityGroups) => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    data: securityGroups
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('securityGroupRfc1918', function () {
    describe('run', function () {
        it('should FAIL if security group allows any reserved private address', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            securityGroupRfc1918.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if security group does not allow any reserved private address', function (done) {
            const cache = createCache([describeSecurityGroups[1]]);
            securityGroupRfc1918.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if security group does not have Ip permissions configured', function (done) {
            const cache = createCache([describeSecurityGroups[2]]);
            securityGroupRfc1918.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should not return any results if unable to describe security groups', function (done) {
            const cache = createNullCache();
            securityGroupRfc1918.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error while describing security groups', function (done) {
            const cache = createErrorCache();
            securityGroupRfc1918.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});