var expect = require('chai').expect;
const launchWizardSecurityGroups = require('./launchWizardSecurityGroups');

const securityGroups = [
          {
            "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
            "GroupName": "launch-wizard-1",
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
            "OwnerId": "123456654321",
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
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "Allows SSh access to developer",
            "GroupName": "spec-test-sg",
            "IpPermissions": [],
            "OwnerId": "123456654321",
            "GroupId": "sg-0b5f2771716acfee4",
            "IpPermissionsEgress": [
              {
                "FromPort": 22,
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
                "ToPort": 22,
                "UserIdGroupPairs": []
              }
            ],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          }
        ];

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

describe('launchWizardSecurityGroups', function () {
    describe('run', function () {
        it('should PASS if security groups was not created using EC2 launch wizard', function (done) {
            const cache = createCache([securityGroups[1]]);
            launchWizardSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if security groups was created using EC2 launch wizard', function (done) {
            const cache = createCache([securityGroups[0]]);
            launchWizardSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no security groups are detected', function (done) {
            const cache = createCache([]);
            launchWizardSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error describing security groups', function (done) {
            const cache = createErrorCache();
            launchWizardSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for security groups', function (done) {
            const cache = createNullCache();
            launchWizardSecurityGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
