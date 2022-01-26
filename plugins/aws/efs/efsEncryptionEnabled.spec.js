var expect = require('chai').expect;
var efsEncryptionEnabled = require('./efsEncryptionEnabled');

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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
        "FileSystemId": "fs-f3fg4ht5",
        "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-f3fg4ht5",
        "CreationTime": "2020-10-18T18:55:19.000Z",
        "LifeCycleState": "available",
        "Name": null
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
  
];


const createCache = (fileSystems) => {
    return {
        efs: {
            describeFileSystems: {
                'us-east-1': {
                    data: fileSystems
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
    };
};

const createNullCache = () => {
    return {
        efs: {
            describeFileSystems: {
                'us-east-1': null,
            },
        },
    };
};

describe('efsEncryptionEnabled', function () {
    describe('run', function () {
        it('should PASS if EFS file systems are encrypted', function (done) {
            const cache = createCache([fileSystems[0]]);
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No unencrypted file systems found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if EFS file system is not encrypted', function (done) {
            const cache = createCache([fileSystems[1]]);
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is unencrypted');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if EFS file systems more than 20 files are not encrypted', function (done) {
            const cache = createCache(fileSystems);
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('More than 20 EFS systems are unencrypted');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no EFS file systems found', function (done) {
            const cache = createCache([]);
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No EFS file systems present');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe file systems', function (done) {
            const cache = createErrorCache();
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if describe file systems response not found', function (done) {
            const cache = createNullCache();
            efsEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});