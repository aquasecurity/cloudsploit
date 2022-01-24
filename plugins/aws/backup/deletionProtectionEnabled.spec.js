var expect = require('chai').expect;
const deletionProtectionEnabled = require('./deletionProtectionEnabled');

const listBackupVaults = [
    {
        "BackupVaultName": "Default",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:Default",
        "CreationDate": "2021-11-26T17:05:36.477000+05:00",
        "EncryptionKeyArn": "arn:aws:kms:us-east-1:000011112222:key/228d6374-d201-428d-b084-842fc7b2d148",
        "CreatorRequestId": "Default",
        "NumberOfRecoveryPoints": 0
    },
    {
        "BackupVaultName": "sadeed1",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed1",
        "CreationDate": "2022-01-21T23:05:24.095000+05:00",
        "EncryptionKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreatorRequestId": "967e0cd4-59c5-471c-8d4d-582a9ee27433",
        "NumberOfRecoveryPoints": 0
    }
];


const getBackupVaultAccessPolicy =[
    {
        "BackupVaultName": "sadeed2",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed2",
        "Policy": {
            "Version":"2012-10-17",
            "Statement":[
                {

                    "Effect": 'Allow',
                    "Principal": '*',
                    "Action": [ 'backup:DeleteRecoveryPoint' ],
                    "Resource": [ '*' ],
                    "Condition": {
                    'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': 'o-lcjto3x5wd/r-z1be/ou-[OU]/*' }
                    }
                },
            ],
        }   
    } ,
    {
        "BackupVaultName": "sadeed2",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed2",
        "Policy": {
            "Version":"2012-10-17",
            "Statement":[
                {

                    "Effect": 'Allow',
                    "Principal": '*',
                    "Action": [ 'backup:CopyIntoBackupVault' ],
                    "Resource": [ '*' ],
                    "Condition": {
                    'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': 'o-lcjto3x5wd/r-z1be/ou-[OU]/*' }
                    }
                },
            ],
        }   
    } 
];

const createCache = (listBackupVaults, getBackupVaultAccessPolicy, listBackupVaultsErr, getBackupVaultAccessPolicyErr) => {
    let name = (listBackupVaults && listBackupVaults.length) ? listBackupVaults[0].BackupVaultName : null;
    return {
        backup: {
            listBackupVaults: {
                'us-east-1': {
                    data: listBackupVaults,
                    err: listBackupVaultsErr
                }
            },
            getBackupVaultAccessPolicy: {
                'us-east-1': {
                    [name]: {
                        data: getBackupVaultAccessPolicy,
                        err: getBackupVaultAccessPolicyErr
                    }
                }
            }
        }
    }
};


describe('deletionProtectionEnabled', function () {
    describe('run', function () {
        it('should PASS if the selected Amazon Backup vault is associated with an access policy, that have deletion protection configured', function (done) {
            const cache = createCache([listBackupVaults[1]], getBackupVaultAccessPolicy[0]);
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('the selected Amazon Backup vault is associated with an access policy, that have deletion protection configured')
                done();
            });
        });

        it('should FAIL if the selected Amazon Backup vault is associated with an access policy, that have no deletion protection configured', function (done) {
            const cache = createCache([listBackupVaults[0]], getBackupVaultAccessPolicy[1] );
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('the selected Amazon Backup vault is associated with an access policy, that have no deletion protection configured')
                done();
            });
        });

        it('should FAIL if Backup vault does not have any policy attached', function (done) {
            const cache = createCache([listBackupVaults[0]], null , null, { message: 'An error occurred (ResourceNotFoundException) when calling the GetBackupVaultAccessPolicy operation', code : 'ResourceNotFoundException' } );
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup vault does not have any policy attached')
                done();
            });
        });


        it('should PASS if no Backup vault list found', function (done) {
            const cache = createCache([]);
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Backup vault list found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Backup vault list', function (done) {
            const cache = createCache(null, { message: 'Unable to query for Backup vault list' });
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Backup vault list')
                done();
            });
        });

        it('should UNKNOWN if Unable to get Backup vault policy', function (done) {
            const cache = createCache([listBackupVaults[0]], null, { message: 'Unable to get Backup vault policy' });
            deletionProtectionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get Backup vault policy')
                done();
            });
        });
    });
});
