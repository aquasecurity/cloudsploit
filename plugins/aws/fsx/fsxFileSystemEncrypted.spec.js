var expect = require('chai').expect;
const fileSystemEncrypted = require('./fsxFileSystemEncrypted');

const describeFileSystems = [
    {
        CreationTime: "2020-12-15T01:16:53.045000+05:00",
        DNSName: "fs-0498eed5fe91001ec.fsx.com",
        FileSystemId: "fs-0498eed5fe91001ec",
        FileSystemType: "WINDOWS",
        KmsKeyId: "arn:aws:kms:us-east-1:012345678912:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        Lifecycle: "AVAILABLE",
        NetworkInterfaceIds: ["eni-abcd1234"],
        OwnerId: "012345678912",
        ResourceARN: "arn:aws:fsx:us-east-1:012345678912:file-system/fs-0498eed5fe91001ec",
        StorageCapacity: 300,
        SubnetIds: ["subnet-1234abcd"],
        Tags: [
            {
                Key: "Name",
                Value: "MyFileSystem"
            }
        ],
        VpcId: "vpc-ab1234cd",
        WindowsConfiguration: {
            ActiveDirectoryId: "d-1234abcd12",
            AutomaticBackupRetentionDays: 30,
            DailyAutomaticBackupStartTime: "05:00",
            ThroughputCapacity: 8,
            WeeklyMaintenanceStartTime: "1:05:00"
        }
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "ad013a33-b01d-4d88-ac97-127399c18b3e",
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
            "Arn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
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
        "KeyArn": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
    }
];

const createCache = (fileSystems, keys, describeKey) => {
    var keyId = (keys && keys.length) ? keys[0].KeyId : null;

    return {
        fsx: {
            describeFileSystems: {
                'us-east-1': {
                    err: null,
                    data: fileSystems
                },
            }
        },
        kms: {
            listKeys: {
                'us-east-1': {
                    data: keys,
                    err: null
                }
            },
            describeKey: {
                'us-east-1': {
                    [keyId]: {
                        err: null,
                        data: describeKey
                    },
                },
            },
        },
    };
};

describe('fileSystemEncrypted', function () {
    describe('run', function () {
        it('should PASS if FSx file system is encrypted with desired encryption level', function (done) {
            const cache = createCache(describeFileSystems, listKeys, describeKey[0]);
            fileSystemEncrypted.run(cache, { fsx_file_systems_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if FSx file system is not encrypted with desired encryption level', function (done) {
            const cache = createCache(describeFileSystems, listKeys, describeKey[1]);
            fileSystemEncrypted.run(cache, { fsx_file_systems_encryption_level : 'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no FSx file system is found', function (done) {
            const cache = createCache([]);
            fileSystemEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list FSx file systems', function (done) {
            const cache = createCache(null, null, null);
            fileSystemEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(describeFileSystems, null, null);
            fileSystemEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
