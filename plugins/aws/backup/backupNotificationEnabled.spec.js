var expect = require('chai').expect;
const backupNotificationEnabled = require('./backupNotificationEnabled');

const listBackupVaults = [
    {
        "BackupVaultName": "sadeed1",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed1",
        "CreationDate": "2022-01-21T23:05:24.095000+05:00",
        "EncryptionKeyArn": "arn:aws:kms:us-east-1:000011112222:key/ad013a33-b01d-4d88-ac97-127399c18b3e",
        "CreatorRequestId": "967e0cd4-59c5-471c-8d4d-582a9ee27433",
        "NumberOfRecoveryPoints": 0
    }
];


const getBackupVaultNotifications =[
    {
        "BackupVaultName": "sadeed2",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed2",
        "SNSTopicArn": "arn:aws:sns:us-east-1:000011112222:mine1.fifo",
        "BackupVaultEvents": [
            "BACKUP_JOB_COMPLETED"
        ]
    },
    {
        "BackupVaultName": "sadeed2",
        "BackupVaultArn": "arn:aws:backup:us-east-1:000011112222:backup-vault:sadeed2",
        "SNSTopicArn": "arn:aws:sns:us-east-1:000011112222:mine1.fifo",
        "BackupVaultEvents": [
            "BACKUP_JOB_FAILED"
        ]
    }
    
];

const createCache = (listBackupVaults, getBackupVaultNotifications, listBackupVaultsErr, getBackupVaultNotificationsErr) => {
    let name = (listBackupVaults && listBackupVaults.length) ? listBackupVaults[0].BackupVaultName : null;
    return {
        backup: {
            listBackupVaults: {
                'us-east-1': {
                    data: listBackupVaults,
                    err: listBackupVaultsErr
                }
            },
            getBackupVaultNotifications: {
                'us-east-1': {
                    [name]: {
                        data: getBackupVaultNotifications,
                        err: getBackupVaultNotificationsErr
                    }
                }
            }
        }
    }
};


describe('backupNotificationEnabled', function () {
    describe('run', function () {
        it('should PASS if Backup vault is configured to send alert notifications for failed Backup job events', function (done) {
            const cache = createCache([listBackupVaults[0]], getBackupVaultNotifications[1]);
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup vault is configured to send alert notifications for failed Backup job events')
                done();
            });
        });

        it('should FAIL if Backup vault is not configured to send alert notifications for failed Backup job events', function (done) {
            const cache = createCache([listBackupVaults[0]], getBackupVaultNotifications[0] );
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup vault is not configured to send alert notifications for failed Backup job events')
                done();
            });
        });

        it('should FAIL if Backup vault does not have any notifications configured', function (done) {
            const cache = createCache([listBackupVaults[0]], null , null, { message: 'An error occurred (ResourceNotFoundException) when calling the getBackupVaultNotifications operation', code : 'ResourceNotFoundException' } );
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup vault does not have any notifications configured')
                done();
            });
        });


        it('should PASS if no Backup vault list found', function (done) {
            const cache = createCache([]);
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Backup vaults found')
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Backup vault list', function (done) {
            const cache = createCache(null, null, { message: 'Unable to query for Backup vault list' });
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Backup vault list')
                done();
            });
        });

        it('should UNKNOWN if Unable to get event notifications for selected Amazon Backup vault', function (done) {
            const cache = createCache([listBackupVaults[0]], null, null, { message: 'Unable to get event notifications for selected Amazon Backup vault' });
            backupNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get event notifications for Backup vault')
                done();
            });
        });
    });
});