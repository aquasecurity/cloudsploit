var expect = require('chai').expect;
const networkAclHasTags = require('./networkAclHasTags');

const describeNetworkAcls = [
    {
        "Associations": [
            {
                "NetworkAclAssociationId": "aclassoc-3ddddf7f",
                "NetworkAclId": "acl-65603818",
                "SubnetId": "subnet-06aa0f60"
            }
        ],
        "Entries": [
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": true,
                "Protocol": "-1",
                "RuleAction": "allow",
                "RuleNumber": 100,
                "PortRange": {
                    "From": 0,
                    "To": 200
                },
            },
        ],
        "IsDefault": true,
        "NetworkAclId": "acl-65603818",
        "Tags": [],
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111122223333"
    },
    {
        "Associations": [
            {
                "NetworkAclAssociationId": "aclassoc-3ddddf7f",
                "NetworkAclId": "acl-65603818",
                "SubnetId": "subnet-06aa0f60"
            }
        ],
        "Entries": [
            {
                "CidrBlock": "0.0.0.0/0",
                "Egress": true,
                "Protocol": "-1",
                "RuleAction": "allow",
                "RuleNumber": 100,
            },
        ],
        "IsDefault": true,
        "NetworkAclId": "acl-65603818",
        "Tags": [{key: "value"}],
        "VpcId": "vpc-99de2fe4",
        "OwnerId": "111122223333"
    }
];

const createCache = (networkAcls) => {
    return {
        ec2: {
            describeNetworkAcls: {
                'us-east-1': {
                    data: networkAcls
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeNetworkAcls: {
                'us-east-1': {
                    err: {
                        message: 'error describing Network ACLs'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeNetworkAcls: {
                'us-east-1': null,
            },
        },
    };
};


describe('networkAclHasTags', function () {
    describe('run', function () {
        it('should FAIL if network ACL does not have tags.', function (done) {
            const cache = createCache([describeNetworkAcls[0]]);

            networkAclHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Network ACL does not have tags')
                done();
            });
        });

        it('should PASS if network ACL have tags', function (done) {
            const cache = createCache([describeNetworkAcls[1]]);

            networkAclHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Network ACL has tags')
                done();
            });
        });

        it('should PASS if no network ACLs found', function (done) {
            const cache = createCache([]);

            networkAclHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Network ACLs found')
                done();
            });
        });

        it('should UNKNOWN if unable to describe network ACLs', function (done) {
            const cache = createErrorCache();

            networkAclHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Network ACLs:')
                done();
            });
        });

    });
});