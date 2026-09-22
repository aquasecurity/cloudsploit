const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Share Soft Deletion Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensure that soft delete feature is enabled for Microsoft Azure file shares.',
    more_info: 'When soft delete for file shares is enabled for a storage account, a deleted file share is retained for the configured retention period before being permanently deleted, allowing data to be recovered if it is deleted by mistake or by a malicious actor.',
    recommended_action: 'Enable soft delete for file shares and set the retention policy to keep deleted file shares for more than desired number of days.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/files/storage-files-prevent-file-share-deletion',
    apis: ['storageAccounts:list', 'fileServices:getServiceProperties'],
    settings: {
        keep_deleted_file_shares_for_days: {
            name: 'Keep Deleted File Shares for Days',
            description: 'Number of days that a deleted file share is retained until it is permanently deleted',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '7'
        }
    },
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftstorage:storageaccounts:fileservices:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            keepForDays: parseInt(settings.keep_deleted_file_shares_for_days || this.settings.keep_deleted_file_shares_for_days.default)
        };

        async.each(locations.storageAccounts, function(location, rcb) {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            storageAccounts.data.forEach(storageAccount => {
                const getServiceProperties = helpers.addSource(cache, source,
                    ['fileServices', 'getServiceProperties', location, storageAccount.id]);

                if (!getServiceProperties || getServiceProperties.err || !getServiceProperties.data) {
                    helpers.addResult(results, 3,
                        `Unable to get file service properties: ${helpers.addError(getServiceProperties)}`,
                        location, storageAccount.id);
                } else {
                    if (getServiceProperties.data.shareDeleteRetentionPolicy &&
                        getServiceProperties.data.shareDeleteRetentionPolicy.enabled &&
                        getServiceProperties.data.shareDeleteRetentionPolicy.days) {
                        const retentionDays = getServiceProperties.data.shareDeleteRetentionPolicy.days;

                        if (retentionDays >= config.keepForDays) {
                            helpers.addResult(results, 0,
                                `File shares deletion policy is configured to persist deleted file shares for ${retentionDays} of ${config.keepForDays} days desired limit`,
                                location, storageAccount.id);
                        } else {
                            helpers.addResult(results, 2,
                                `File shares deletion policy is configured to persist deleted file shares for ${retentionDays} of ${config.keepForDays} days desired limit`,
                                location, storageAccount.id);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'File shares soft delete feature is not enabled for Storage Account',
                            location, storageAccount.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
