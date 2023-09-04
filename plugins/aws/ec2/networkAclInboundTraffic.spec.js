var expect = require('chai').expect;
const networkAclInboundTraffic = require('./networkAclInboundTraffic');

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
                "Egress": false,
                "Protocol": "-1",
                "RuleAction": "allow",
                "RuleNumber": 100,
                "PortRange": {
                    "From": 0, //No open remote admin port in range 0-10
                    "To": 10
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
                "Egress": false,
                "Protocol": "-1",
                "RuleAction": "allow",
                "RuleNumber": 100,
                "PortRange": {
                    "From": 0, // Fail because of SSH
                    "To": 100
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
                "Egress": true, //Pass because egress
                "Protocol": "-1",
                "RuleAction": "allow",
                "RuleNumber": 100,
                "PortRange": {
                    "From": 0,
                    "To": 100
                },
            },

        ],
        "IsDefault": true,
        "NetworkAclId": "acl-65603818",
        "Tags": [],
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


describe('networkAclInboundTraffic', function () {
    describe('run', function () {
        it('should PASS if network ACL does not allow unrestricted access', function (done) {
            const cache = createCache([describeNetworkAcls[0]]);

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if network ACL allows unrestricted access egress is disabled', function (done) {
            const cache = createCache([describeNetworkAcls[1]]);

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if network ACL has no ingress rules', function (done) {
            const cache = createCache([describeNetworkAcls[2]]);

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no network ACLs found', function (done) {
            const cache = createCache([]);

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe network ACLs', function (done) {
            const cache = createErrorCache();

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe network ACLs response is not found', function (done) {
            const cache = createNullCache();

            networkAclInboundTraffic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
