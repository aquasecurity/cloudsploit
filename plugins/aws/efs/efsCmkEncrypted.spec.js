var expect = require('chai').expect;
var efsCmkEncrypted = require('./efsCmkEncrypted');

const fileSystems = [
    {
        "OwnerId": "112233445566",
        "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
        "FileSystemId": "fs-61dff6e3",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-61dff6e3",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null,
        "PerformanceMode": "generalPurpose",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467"
    },
    {
        "OwnerId": "112233445566",
        "CreationToken": "quickCreated-c6e60995-a5eb-478c-8b60-2464510ebb58",
        "FileSystemId": "fs-30f3dab2",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-30f3dab2",
        "CreationTime": "2020-10-18T17:53:27.000Z",
        "LifeCycleState": "available",
        "Name": "",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/080891c0-b3a8-42a3-91be-c23aa7b46d3f"
    },
    {
        "OwnerId": "112233445566",
        "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
        "FileSystemId": "fs-76ffd6d5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-76ffd6d5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null,
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/143947b8-b22b-4360-9835-af7d346092f9"
    },
    {
        "OwnerId": "112233445566",
        "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
    },
    {
        "OwnerId": "112233445566",
        "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
        "FileSystemId": "fs-61dff6e3",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-61dff6e3",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "PerformanceMode": "generalPurpose",
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/080891c0-b3a8-42a3-91be-c23aa7b46d3f"
    },
    {
        "OwnerId": "112233445566",
        "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
        "FileSystemId": "fs-61dff6e3",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-61dff6e3",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "Name": null,
        "Encrypted": true,
        "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/12345678-b3a8-42a3-91be-c23aa7b46d3f"
    }
];

const listAliases = [
    {
        "AliasName": "alias/efsKmsKey",
        "AliasArn": "arn:aws:kms:us-east-1:112233445566:alias/efsKmsKey",
        "TargetKeyId": "60c4f21b-e271-4e97-86ae-6403618a9467"
    },
    {
        "AliasName": "alias/aws/elasticfilesystem",
        "AliasArn": "arn:aws:kms:us-east-1:112233445566:alias/aws/elasticfilesystem",
        "TargetKeyId": "080891c0-b3a8-42a3-91be-c23aa7b46d3f"
    },
];

const createCache = (fileSystems, kmsAliases) => {
    return {
        efs: {
            describeFileSystems: {
                'us-east-1': {
                    data: fileSystems
                },
            },
        },
        kms: {
            listAliases: {
                'us-east-1': {
                    data: kmsAliases
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        efs: {
            describeFileSystems: {
                'us-east-1': {
                    err: {
                        message: 'error while describing EFS file systems'
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
        efs: {
            describeFileSystems: {
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

describe('efsCmkEncrypted', function () {
    describe('run', function () {
        it('should PASS if all EFS file systems are using Customer Master Key for encryption', function (done) {
            const cache = createCache([fileSystems[0]], [listAliases[0]]);
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
        
        it('should FAIL if EFS file system is not using Customer Master Key for encryption', function (done) {
            const cache = createCache([fileSystems[1]], [listAliases[1]]);
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
                
        it('should FAIL if number of AWS managed key encrypted EFS file systems is more than threshold', function (done) {
            const cache = createCache([fileSystems[1], fileSystems[4]], listAliases);
            efsCmkEncrypted.run(cache, { cmk_unencrypted_threshold: 1 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should FAIL if EFS file systems is referencing deleted KMS keys', function (done) {
            const cache = createCache([fileSystems[5]], listAliases);
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });
        

        it('should PASS if no EFS file systems found', function (done) {
            const cache = createCache([]);
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe file systems', function (done) {
            const cache = createErrorCache();
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe file systems response not found', function (done) {
            const cache = createNullCache();
            efsCmkEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});