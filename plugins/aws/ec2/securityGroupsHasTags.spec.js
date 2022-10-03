var expect = require('chai').expect;
const securityGroupsHasTags = require('./securityGroupsHasTags');

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4",
        "Tags": []
    },
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4",
        "Tags": [{key: "Key", value: "value"}]
    },
];

const createCache = (groups) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    data: groups,
                    err: null,
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

describe('securityGroupsHasTags', function () {
    describe('run', function () {
        it('should PASS if default security group has Tags', function (done) {
            const cache = createCache([describeSecurityGroups[1]]);
            securityGroupsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if default security group does not Tags', function (done) {
            const cache = createCache([describeSecurityGroups[0]]);
            securityGroupsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            securityGroupsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createErrorCache();
            securityGroupsHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

    });
});
