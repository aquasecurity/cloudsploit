var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Failure Notification Enabled',
    category: 'Backup',
    domain: 'Storage',
    severity: 'LOW',
    description: 'Ensure that Amazon Backup vaults send notifications via Amazon SNS for each failed backup job event.',
    more_info: 'AWS Backup can take advantage of the robust notifications delivered by Amazon Simple Notification Service (Amazon SNS). You can configure Amazon SNS to notify you of AWS Backup events from the Amazon SNS console.',
    recommended_action: 'Configure Backup vaults to sent notifications alert for failed backup job events.',
    link: 'https://docs.aws.amazon.com/aws-backup/latest/devguide/sns-notifications.html',
    apis: ['Backup:listBackupVaults', 'Backup:getBackupVaultNotifications' ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.backup, function(region, rcb){
            var listBackupVaults = helpers.addSource(cache, source,
                ['backup', 'listBackupVaults', region]);

            if (!listBackupVaults) return rcb();

            if (listBackupVaults.err || !listBackupVaults.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Backup vault list: ${helpers.addError(listBackupVaults)}`, region);
                return rcb();
            }

            if (!listBackupVaults.data.length) {
                helpers.addResult(results, 0, 'No Backup vaults found', region);
                return rcb();
            }

            for (let vault of listBackupVaults.data){
                if (!vault.BackupVaultArn) continue;

                let resource = vault.BackupVaultArn;

                let getBackupVaultNotifications = helpers.addSource(cache, source,
                    ['backup', 'getBackupVaultNotifications', region, vault.BackupVaultName]);

                if (getBackupVaultNotifications && getBackupVaultNotifications.err && getBackupVaultNotifications.err.code &&
                    getBackupVaultNotifications.err.code == 'ResourceNotFoundException') {
                    helpers.addResult(results, 2,
                        'Backup vault does not have any notifications configured', region, resource);
                    continue;
                }

                if (!getBackupVaultNotifications || getBackupVaultNotifications.err || !getBackupVaultNotifications.data || !getBackupVaultNotifications.data.BackupVaultEvents) {
                    helpers.addResult(results, 3, `Unable to get event notifications for Backup vault: ${helpers.addError(getBackupVaultNotifications)}`, region, resource);
                    continue;
                }

                if (getBackupVaultNotifications.data.BackupVaultEvents.find(notification => notification && notification.toUpperCase() == 'BACKUP_JOB_FAILED')) {
                    helpers.addResult(results, 0,
                        'Backup vault is configured to send alert notifications for failed Backup job events',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Backup vault is not configured to send alert notifications for failed Backup job events',
                        region, resource);
                }    

            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};