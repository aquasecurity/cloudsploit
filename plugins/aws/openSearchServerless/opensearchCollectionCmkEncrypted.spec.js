const expect = require('chai').expect;
var collectionCmkEncrypted = require('./opensearchCollectionCmkEncrypted');

const listCollections = [
    {
       "arn": 'arn:aws:aoss:us-east-1:000011112222:collection:testing-123',
       "id": "123xyz",
       "name": "auto-test",
       "status": "ACTIVE"
    },
];
const listSecurityPolicies =[
    {
        "name": "auto-test",
        "type": "encryption",
    }
]
const listKeys = [
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
            "KeyId": "2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9",
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

const getSecurityPolicy = [
    
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: { Rules: [{ Resource:["collection/test"], ResourceType:'collection' }], AWSOwnedKey: true },
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'encryption'
        }
    },
    {
        securityPolicyDetail: {
            createdDate: 1677926608534,
            description: 'testPolicy',
            lastModifiedDate: 1677926608534,
            name: 'auto-test',
            policy: { Rules: [{ Resource:["collection/auto-test"], ResourceType:'collection' }], KmsARN: 'arn:aws:kms:us-east-1:000011112222:key/2cff2321-73c6-4bac-95eb-bc9633d3e8a9'},
            policyVersion: 'MTY3NzkyNjYwODUzNF8x',
            type: 'network'
        }
    }
]

const createCache = (listCollections, listSecurityPolicies, getSecurityPolicy,  keys, describeKey) => {
    var keyId = (getSecurityPolicy && getSecurityPolicy.securityPolicyDetail.policy.KmsARN) ?
     getSecurityPolicy.securityPolicyDetail.policy.KmsARN.split('/')[1] : null;
    return {
        opensearchserverless: {
            listCollections: {
                'us-east-1': {
                    data: listCollections
                }
            },
            listEncryptionSecurityPolicies: {
                'us-east-1': {
                    data: listSecurityPolicies               
                }
            },
            getEncryptionSecurityPolicy: {
                'us-east-1': {
                    "auto-test":{
                        data: getSecurityPolicy
                    }
                }
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
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

describe('collectionCmkEncrypted', function () {
    describe('run', function () {

        it('should give Unknown result if unable to list collections', function (done) {
            const cache = createCache(null);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query list OpenSearch collections');
                done();
            });
        });

        it('should Pass if no collection found', function (done) {
            const cache = createCache([]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No OpenSearch Collection found');
                done();
            });
        });

        it('should give UNKNOWN result if unable to list security Policies', function (done) {
            const cache = createCache(listCollections, null);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query list OpenSearch security policy:');
                done();
            });
        });

        it('should PASS if no security policy found', function (done) {
            const cache = createCache(listCollections, []);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No OpenSearch Security Policy found');
                done();
            });
        });
        it('should give UNKNOWN result if unable to query get security policy', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, null, listKeys);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query get OpenSearch security policy:');
                done();
            });
        });
        it('should PASS if collection is publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[1], listKeys, describeKey[0]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenSearch Collection is encrypted with awscmk');
                done();
            });
        });
        it('should FAIL if collection is not publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[0], listKeys, describeKey[1]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenSearch Collection is encrypted with awskms');
                done();
            });
        });
         it('should give Unknown if collection is not publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[0], null, describeKey[1]);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list KMS keys');
                done();
            });
        });
         it('should give Unknown if collection is not publically accessible', function (done) {
            const cache = createCache(listCollections, listSecurityPolicies, getSecurityPolicy[1], listKeys);
            collectionCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query KMS key');
                done();
            });
        });

    });
});