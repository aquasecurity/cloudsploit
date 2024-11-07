var expect = require('chai').expect;
var networkMemberCloudwatchLogs = require('./networkMemberCloudwatchLogs');

const listNetworks = [
    {
        "Id": "n-Z7YTJ3EHSBENRKI7UM6XW2XWFQ",
        "Name": "akhtar-net",
        "Description": null,
        "Framework": "HYPERLEDGER_FABRIC",
        "FrameworkVersion": "1.4",
        "Status": "AVAILABLE",
        "CreationDate": "2021-11-16T07:46:51.158Z",
        "Arn": "arn:aws:managedblockchain:us-east-1::networks/n-Z7YTJ3EHSBENRKI7UM6XW2XWFQ"
    }
];

const listMembers = [
    {
        "Id": "m-3WDFHOCKPZFPXOXP5SVIYEBTYA",
        "Name": "akhtar",
        "Description": null,
        "Status": "AVAILABLE",
        "CreationDate": "2021-11-16T07:46:51.146Z",
        "IsOwned": true,
        "Arn": "arn:aws:managedblockchain:us-east-1:000011112222:members/m-3WDFHOCKPZFPXOXP5SVIYEBTYA"
    }
];

const getMember = [
    {
        "NetworkId": "n-Z7YTJ3EHSBENRKI7UM6XW2XWFQ",
        "Id": "m-3WDFHOCKPZFPXOXP5SVIYEBTYA",
        "Name": "akhtar",
        "Description": null,
        "FrameworkAttributes": {
          "Fabric": {
            "AdminUsername": "cloudsploit",
            "CaEndpoint": "ca.m-3wdfhockpzfpxoxp5sviyebtya.n-z7ytj3ehsbenrki7um6xw2xwfq.managedblockchain.us-east-1.amazonaws.com:30002"
          }
        },
        "LogPublishingConfiguration": {
          "Fabric": {
            "CaLogs": {
              "Cloudwatch": {
                "Enabled": true
              }
            }
          }
        },
        "Status": "AVAILABLE",
        "CreationDate": "2021-11-16T07:46:51.146Z",
        "Tags": {},
        "Arn": "arn:aws:managedblockchain:us-east-1:000011112222:members/m-3WDFHOCKPZFPXOXP5SVIYEBTYA",
        "KmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    },
    {
        "NetworkId": "n-Z7YTJ3EHSBENRKI7UM6XW2XWFQ",
        "Id": "m-3WDFHOCKPZFPXOXP5SVIYEBTYA",
        "Name": "akhtar",
        "Description": null,
        "FrameworkAttributes": {
          "Fabric": {
            "AdminUsername": "cloudsploit",
            "CaEndpoint": "ca.m-3wdfhockpzfpxoxp5sviyebtya.n-z7ytj3ehsbenrki7um6xw2xwfq.managedblockchain.us-east-1.amazonaws.com:30002"
          }
        },
        "LogPublishingConfiguration": {
          "Fabric": {
            "CaLogs": {
              "Cloudwatch": {
                "Enabled": false
              }
            }
          }
        },
        "Status": "AVAILABLE",
        "CreationDate": "2021-11-16T07:46:51.146Z",
        "Tags": {},
        "Arn": "arn:aws:managedblockchain:us-east-1:000011112222:members/m-3WDFHOCKPZFPXOXP5SVIYEBTYA",
        "KmsKeyArn": "AWS_OWNED_KMS_KEY"
    }
];


const createCache = (networks, members, getMember, networksErr) => {
    var networkId = (networks && networks.length) ? networks[0].Id : null;
    var memberId = (members && members.length) ? members[0].Id : null;
    return {
        managedblockchain: {
            listNetworks: {
                'us-east-1': {
                    err: networksErr,
                    data: networks
                },
            },
            listMembers: {
                'us-east-1': {
                    [networkId]: {
                        data: {
                            "Members": members
                        }
                    }
                }
            },
            getMember: {
                'us-east-1': {
                    [memberId]: {
                        data: {
                            "Member": getMember
                        }
                    }
                }
            }
        },
    };
};

describe('networkMemberCloudwatchLogs', function () {
    describe('run', function () {
        it('should PASS if Network member has cloudwatch logs enabled', function (done) {
            const cache = createCache(listNetworks ,listMembers, getMember[0]);
            networkMemberCloudwatchLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Network member has CloudWatch logs enabled');
                done();
            });
        });

        it('should FAIL if Network member does not have cloudwatch logs enabled', function (done) {
            const cache = createCache(listNetworks ,listMembers, getMember[1]);
            networkMemberCloudwatchLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Network member does not have CloudWatch logs enabled');
                done();
            });
        });

        it('should PASS if no Managed Blockchain networks found', function (done) {
            const cache = createCache([]);
            networkMemberCloudwatchLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Managed Blockchain networks found');
                done();
            });
        });

        it('should UNKNOWN if unable to query Managed Blockchain networks', function (done) {
            const cache = createCache(null, null, null, { message: "unable to obtain data" });
            networkMemberCloudwatchLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Managed Blockchain networks:');
                done();
            });
        });

    });
})