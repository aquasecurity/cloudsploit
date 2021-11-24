var expect = require('chai').expect;
var ledgerEncrypted = require('./ledgerEncrypted');

const listLedgers = [   
    {
        "Name": "sadeed1",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00" 
    } 
];

const describeLedger = [
    {
        "Name": "sadeed1",
        "Arn": "arn:aws:qldb:us-east-1:000111222333:ledger/sadeed1",
        "State": "ACTIVE",
        "CreationDateTime": "2021-11-19T16:29:08.899000+05:00",
        "PermissionsMode": "STANDARD",
        "DeletionProtection": true,
        "EncryptionDescription": {
            "KmsKeyArn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
            "EncryptionStatus": "ENABLED"
        }
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

const createCache = (ledgers, keys, describeLedger, describeKey, ledgersErr, keysErr, describeKeyErr, describeLedgerErr) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;
    var name = (ledgers && ledgers.length) ? ledgers[0].Name: null;
    return {
        qldb: {
            listLedgers: {
                'us-east-1': {
                    err: ledgersErr,
                    data: ledgers
                },
            },
            describeLedger: {
                'us-east-1': {
                    [name]: {
                        data: describeLedger,
                        err: describeLedgerErr
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

describe('ledgerEncrypted', function () {
    describe('run', function () {
        it('should PASS if QLDB ledger is encrypted with desired encryption level', function (done) {
            const cache = createCache(listLedgers, listKeys, describeLedger[0], describeKey[0]);
            ledgerEncrypted.run(cache, { qldb_ledger_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if QLDb ledger is not encrypted with desired encryption level', function (done) {
            const cache = createCache(listLedgers,listKeys, describeLedger[0], describeKey[1]);
            ledgerEncrypted.run(cache, { qldb_ledger_desired_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no QLDB ledgers found', function (done) {
            const cache = createCache([]);
            ledgerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list  QLDB ledgers', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list QLDB ledgers" });
            ledgerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(listLedgers, null, null, null, { message: "Unable to list KMS keys" });
            ledgerEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
})
