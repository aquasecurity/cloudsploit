var expect = require('chai').expect;
const backupVaultHasTags = require('./backupVaultHasTags');

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
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:Default",
        "CreationDate": "2022-01-21T23:05:24.095000+05:00",
        "EncryptionKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreatorRequestId": "967e0cd4-59c5-471c-8d4d-582a9ee27433",
        "NumberOfRecoveryPoints": 0
    }
];


const resourcegroupstaggingapi =[
    {
        "ResourceARN": "arn:aws:backup:us-east-1:000011112222:backup-vault:Default",
        "Tags": [{key:"key1", value:"value"}],
    },
    {
        "ResourceARN": "arn:aws:backup:us-east-1:000011112222:backup-vault:Default",
        "Tags": [],
    }
];

const createCache = (listBackupVaults, rgData) => {
    return {
        backup: {
            listBackupVaults: {
                'us-east-1': {
                    data: listBackupVaults,
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        }
    }
};


describe('backupVaultHasTags', function () {
    describe('run', function () {
        it('should PASS if Backup vault have tags', function (done) {
            const cache = createCache([listBackupVaults[0]], [resourcegroupstaggingapi[0]]);
            backupVaultHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup Vault has tags')
                done();
            });
        });

        it('should FAIL if Backup vault does not have tags', function (done) {
            const cache = createCache([listBackupVaults[0]], [resourcegroupstaggingapi[1]] );
            backupVaultHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup Vault does not have any tags')
                done();
            });
        });


        it('should PASS if no Backup vault list found', function (done) {
            const cache = createCache([], null);
            backupVaultHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Backup vaults found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Backup vault list', function (done) {
            const cache = createCache(null, null);
            backupVaultHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list Backup vaults')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listBackupVaults[0]], null);
            backupVaultHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources from group tagging api')
                done();
            });
        });
    });
});
