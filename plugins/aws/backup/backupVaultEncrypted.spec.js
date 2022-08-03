var expect = require('chai').expect;
var backupVaultEncrypted = require('./backupVaultEncrypted');

const listBackupVaults = [
    {
        BackupVaultName: 'sadeed-vault',
        BackupVaultArn: 'arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed-vault',
        CreationDate: '2021-11-08T10:12:46.700Z',
        EncryptionKeyArn: 'arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250'
    },
    {
        BackupVaultName: "aws/efs/automatic-backup-vault",
        BackupVaultArn: "arn:aws:backup:us-east-1:000011112222:backup-vault:aws/efs/automatic-backup-vault",
        CreationDate: "2020-10-18T10:53:45.887000-07:00",
        EncryptionKeyArn: "arn:aws:kms:us-east-1:000011112222:key/f4942dd6-bce5-4213-bdd3-cc8ccd87dd89"
    }
];

const describeKey = [
    {
        "KeyMetadata": {
            "AWSAccountId": "000011112222",
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
            "KeyId": "c4750c1a-72e5-4d16-bc72-0e7b559e0250",
            "Arn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
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
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250"
    },
    {
        "KeyId": "0604091b-8c1b-4a55-a844-8cc8ab1834d9",
        "KeyArn": "arn:aws:kms:us-east-1:000011112222:key/f4942dd6-bce5-4213-bdd3-cc8ccd87dd890"
    }
]

const createCache = (backupVault, keys, describeKey, backupVaultErr, keysErr, describeKeyErr) => {
    var keyId = (backupVault && backupVault.length) ? backupVault[0].EncryptionKeyArn.split('/')[1] : null;
    return {
        backup: {
            listBackupVaults: {
                'us-east-1': {
                    err: backupVaultErr,
                    data: backupVault
                },
            },
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

describe('backupVaultEncrypted', function () {
    describe('run', function () {
        it('should PASS if Backup Vault is encrypted with desired encryption level', function (done) {
            const cache = createCache([listBackupVaults[0]], listKeys, describeKey[0]);
            backupVaultEncrypted.run(cache, { backup_vault_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Backup vault is encrypted with awscmk');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Backup Vault is not encrypted with desired encyption level', function (done) {
            const cache = createCache([listBackupVaults[0]], listKeys, describeKey[1]);
            backupVaultEncrypted.run(cache, { backup_vault_desired_encryption_level:'awscmk' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Backup vault is encrypted with awskms');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Backup vault  found', function (done) {
            const cache = createCache([]);
            backupVaultEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Backup vaults found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Backup vault', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list Backup vault encryption" });
            backupVaultEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list KMS keys', function (done) {
            const cache = createCache(null, null, null, { message: "Unable to list KMS keys" });
            backupVaultEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
}); 