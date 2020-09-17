var expect = require('chai').expect;
var rdsCmkEncryptionEnabled = require('./rdsCmkEncryptionEnabled');

const describeDBInstances = [
    {
        "Engine": "mysql",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:012345678910:key/abcdef10-1517-49d8-b085-77c50b904149",
    },
    {
        "Engine": "mysql",
        "StorageEncrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:012345678910:key/88888888-1517-49d8-b085-77c50b904149",
    },
    {
        "Engine": "mysql",
        "StorageEncrypted": false,
    }
];

const listAliases = [
    {
        AliasArn: "arn:aws:kms:us-east-1:012345678910:alias/example1", 
        AliasName: "custom/key", 
        TargetKeyId: "abcdef10-1517-49d8-b085-77c50b904149"
    },
    {
        AliasArn: "arn:aws:kms:us-east-1:012345678910:alias/customRdsKey", 
        AliasName: "alias/aws/rds", 
        TargetKeyId: "abcdef10-1517-49d8-b085-77c50b904149"
    }
];

const createCache = (rdsInstances, kmsAliases) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: null,
                    data: rdsInstances
                },
            },
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: null,
                    data: kmsAliases
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    err: {
                        message: 'error while describing RDS instances'
                    },
                },
            },
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    err: {
                        message: 'error while listing KMS aliases'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': null,
            },
        },
        kms: {
            listAliases: {
                'us-east-1': null,
            },
        },
    };
};

describe('rdsCmkEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if RDS instance is encrypted at rest via KMS Customer Master Key', function (done) {
            const cache = createCache([describeDBInstances[0]], [listAliases[0]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should PASS if RDS instance is encrypted at rest via default KMS key', function (done) {
            const cache = createCache([describeDBInstances[0]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
                
        it('should FAIL if RDS instance encryption key is not found', function (done) {
            const cache = createCache([describeDBInstances[1]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
                
        it('should FAIL if RDS instance does not have encryption enabled', function (done) {
            const cache = createCache([describeDBInstances[2]], [listAliases[1]]);
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS instances', function (done) {
            const cache = createErrorCache();
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if no RDS instance found', function (done) {
            const cache = createNullCache();
            rdsCmkEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});