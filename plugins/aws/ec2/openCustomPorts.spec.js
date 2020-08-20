var expect = require('chai').expect;
const openCustomPorts = require('./openCustomPorts');

const securityGroups = [
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
            "UserIdGroupPairs": []
        }],
        "OwnerId": "560213429563",
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
    },
    {
        "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
        "GroupName": "launch-wizard-1",
        "IpPermissions": [
            {
                "FromPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 80,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "560213429563",
        "GroupId": "sg-0ff1642cae23c309a",
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

const createCache = (groups) => {
    return {
        ec2: {
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
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing cloudformation stacks'
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

describe('openCustomPorts', function () {
    describe('run', function () {

        it('should not return any results if unable to fetch any security groups description', function (done) {
            const cache = createNullCache();
            openCustomPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error occurs while fetching any security groups description', function (done) {
            const cache = createErrorCache();
            openCustomPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no security groups are present', function (done) {
            const cache = createCache([]);
            openCustomPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if any public open port is found', function (done) {
            const cache = createCache([securityGroups[0]]);
            openCustomPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no public open port is found', function (done) {
            const cache = createCache([securityGroups[1]]);
            openCustomPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});