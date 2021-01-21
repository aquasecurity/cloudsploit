var expect = require('chai').expect;
const openPostgreSQL = require('./openPostgreSQL');

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
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
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-001639e564442dfec",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-001639e564442dfec",
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
];

const createCache = (securityGroups, securityGroupsErr) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    err: securityGroupsErr,
                    data: securityGroups
                }
            },
        }
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

describe('openPostgreSQL', function () {
    describe('run', function () {
        it('should PASS if no public open ports found', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            openPostgreSQL.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if security group has PostgreSQL TCP port open to public', function (done) {
            const cache = createCache([describeSecurityGroups[1]]);
            openPostgreSQL.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openPostgreSQL.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createCache(null, { message: 'Unable to describe security groups'});
            openPostgreSQL.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            openPostgreSQL.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
