var expect = require('chai').expect;
var customerProfilesDomainEncrypted = require('./customerProfilesDomainEncrypted');

const listDomains = [   
    { 
        "DomainName": "mine2",
        "CreatedAt": "2021-11-19T14:43:41.751000+05:00",
        "LastUpdatedAt": "2021-11-19T14:43:41.751000+05:00",
        "Tags": {}  
    } 
];

const getDomain = [
    {
        "DomainName": "mine2",
        "DefaultExpirationDays": 366,
        "DefaultEncryptionKey": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "Stats": {
            "ProfileCount": 0,
            "MeteringProfileCount": 0,
            "ObjectCount": 0,
            "TotalSize": 0
        },
        "CreatedAt": "2021-11-19T14:43:41.751000+05:00",
        "LastUpdatedAt": "2021-11-19T14:43:41.751000+05:00",
        "Tags": {}
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
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
    },
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "Default master key that protects my Glue data when no other key is defined",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeyState": "Enabled",
            "Origin": "AWS_KMS",
            "KeyManager": "AWS",
            "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
            "EncryptionAlgorithms": [
                "SYMMETRIC_DEFAULT"
            ]
        }
    }
];

const listKeys = [
    {
        "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
]

const createCache = (domains, keys, getDomain, describeKey, domainsErr, keysErr, describeKeyErr, getDomainErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var DomainName = (domains && domains.length) ? domains[0].DomainName: null;
    return {
        customerprofiles: {
            listDomains: {
                'us-east-1': {
                    err: domainsErr,
                    data: domains
                },
            },
            getDomain: {
                'us-east-1': {
                    [DomainName]: {
                        data: getDomain,
                        err: getDomainErr
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
                        err: describeKeyErr,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('customerProfilesDomainEncrypted', function () {
    describe('run', function () {
        it('should PASS if CustomerProfiles domain is encrypted with desired encryption level', function (done) {
            const cache = createCache(listDomains, listKeys, getDomain[0], describeKey[0]);
            customerProfilesDomainEncrypted.run(cache, { customer_profiles_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if CustomerProfiles domain is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listDomains,listKeys, getDomain[0], describeKey[1]);
            customerProfilesDomainEncrypted.run(cache, { customer_profiles_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no CustomerProfiles domain found', function (done) {
            const cache = createCache([]);
            customerProfilesDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list CustomerProfiles domain', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list CustomerProfiles domain" });
            customerProfilesDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listDomains, null, null, null, { message: "Unable to list KMS keys" });
            customerProfilesDomainEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
