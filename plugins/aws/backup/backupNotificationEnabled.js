var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup Notification Enabled',
    category: 'Backup',
    domain: 'Storage',
    description: 'Ensure your Amazon Backup vaults send notifications via Amazon SNS for each failed backup job',
    more_info: 'AWS Backup takes advantage of the robust notifications delivered by Amazon Simple Notification Service (Amazon SNS). You can configure Amazon SNS to notify you of AWS Backup events from the Amazon SNS console.',
    recommended_action: 'Set up notifications alert for failed backup jobs',
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
                helpers.addResult(results, 0, 'No Backup vault list found', region);
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
                        'Event notifications are not enabled for the selected Amazon Backup vault', region, resource);
                    continue;
                }

                if (!getBackupVaultNotifications || getBackupVaultNotifications.err || !getBackupVaultNotifications.data) {
                    helpers.addResult(results, 3, `Unable to get event notifications for selected Amazon Backup vault: ${helpers.addError(getBackupVaultNotifications)}`, region, resource);
                    continue;
                }

                if (getBackupVaultNotifications.data &&
                    getBackupVaultNotifications.data.BackupVaultEvents[0].toUpperCase() == 'BACKUP_JOB_COMPLETED'  ) {
                    helpers.addResult(results, 0,
                        'Selected vault is configured to send alert notifications for failed Backup jobs',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Selected vault is not configured to send alert notifications for failed Backup jobs',
                        region, resource);
                }    

            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};