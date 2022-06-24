var expect = require('chai').expect;
var esDomainEncryptionEnabled = require('./esDomainEncryptionEnabled');

const domains =  [
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true,
                KmsKeyId: 'arn:aws:kms:us-east-1:111122223333:key/34e9wedw-ae6b-4c36-9405-06e67bccswwd'
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true,
                KmsKeyId: 'arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1'
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: false
            }
        }
    },
    {
        DomainStatus: {
            DomainName: 'mydomain',
            ARN: 'arn:1234',
            EncryptionAtRestOptions: {
                Enabled: true
            }
        }
    }
]

const domainNames = [
    {
        DomainName: 'mydomain'
    }
]


const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "111122223333",
            "KeyId": "34e9wedw-ae6b-4c36-9405-06e67bccswwd",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/34e9wedw-ae6b-4c36-9405-06e67bccswwd",
            "CreationDate": "2020-12-15T01:16:53.045000+05:00",
            "Enabled": true,
            "Description": "My key",
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
            "AWSAccountId": "111122223333",
            "KeyId": "75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
            "Arn": "arn:aws:kms:us-east-1:111122223333:key/75e9285f-ae6b-4c36-9405-06e67bcc7ef1",
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
]

const createCache = (listData, descData, describeKey) => {
    var keyId = ( descData && descData.DomainStatus && 
        descData.DomainStatus.EncryptionAtRestOptions &&
        descData.DomainStatus.EncryptionAtRestOptions.KmsKeyId) ? descData.DomainStatus.EncryptionAtRestOptions.KmsKeyId.split('/')[1] : null;
    
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    'mydomain': {
                        err: null,
                        data: descData
                    }
                }
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        data: describeKey
                    },
                },
            },
        },
    }
};

const createErrorCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    err: {
                        message: 'error describing domain names'
                    },
                },
            }
        },
        kms: {
            describeKey: {
                'us-east-1': {
                    err: {
                        message: 'error describing keys'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
            describeElasticsearchDomain: {
                'us-east-1': null
            }
        },
        kms: {
            describeKey: {
                'us-east-1': null
            }
        },
    };
}

describe('esDomainEncryptionEnabled', function () {
    describe('run', function () {
        
        it('should PASS if ES domain has encryption at rest at an encryption level greater than or equal to target encryption level', function (done) {
            const cache = createCache([domainNames[0]], domains[1], describeKey[0]);
            esDomainEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no ES domains present', function (done) {
            const cache = createCache([], {});
            esDomainEncryptionEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if ES encryption config is disabled', function (done) {
            const cache = createCache([domainNames[0]], domains[2], describeKey[0]);
            esDomainEncryptionEnabled.run(cache, {}, (err, results) => {;
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if ES domain has encryption at rest at an encryption level greater than target encryption level', function (done) {
            const cache = createCache([domainNames[0]], domains[0], describeKey[1]);
            esDomainEncryptionEnabled.run(cache, {es_encryption_level: 'awscmk'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to list domain names', function (done) {
            const cache = createErrorCache();
            esDomainEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if list domain names response not found', function (done) {
            const cache = createNullCache();
            esDomainEncryptionEnabled.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    })
})