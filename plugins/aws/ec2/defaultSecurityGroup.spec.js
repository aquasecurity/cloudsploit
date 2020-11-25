var expect = require('chai').expect;
const defaultSecurityGroup = require('./defaultSecurityGroup');

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

describe('defaultSecurityGroup', function () {
    describe('run', function () {
        it('should PASS if default security group has inbound or outbound rules', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if default security group does not have inbound or outbound rules', function (done) {
            const cache = createCache([describeSecurityGroups[1]]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createErrorCache();
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            defaultSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
