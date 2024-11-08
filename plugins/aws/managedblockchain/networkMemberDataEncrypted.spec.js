var expect = require('chai').expect;
var networkMemberDataEncrypted = require('./networkMemberDataEncrypted');

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
                "Enabled": false
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

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "CUSTOMER",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (networks, members, getMember, keys, describeKey, networksErr, keysErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyArn.split('/')[1] : null;
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
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: keysErr
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('networkMemberDataEncrypted', function () {
    describe('run', function () {
        it('should PASS if Network member is using desired encryption level', function (done) {
            const cache = createCache(listNetworks ,listMembers, getMember[0], listKeys, describeKey[0]);
            networkMemberDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Network member is not using desired encryption level', function (done) {
            const cache = createCache(listNetworks ,listMembers, getMember[1], listKeys, describeKey[0]);
            networkMemberDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Managed Blockchain networks found', function (done) {
            const cache = createCache([]);
            networkMemberDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to query Managed Blockchain networks', function (done) {
            const cache = createCache(null, null, null, null, null, { message: "unable to obtain data" });
            networkMemberDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, null, null, null, { message: "Unable to list KMS keys" });
            networkMemberDataEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})