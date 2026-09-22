const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Account Key Rotation Reminder',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that key rotation reminders are enabled for Microsoft Azure Storage Accounts.',
    more_info: 'Access keys authenticate application access requests to data contained in storage accounts. Setting a key rotation reminder helps maintain a regular cadence for regenerating access keys, so that a potentially compromised key cannot be used as a long-term credential.',
    recommended_action: 'Enable key rotation reminders from the access keys settings of the storage account and set the reminder period to the desired number of days.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage',
    apis: ['storageAccounts:list'],
    settings: {
        storage_account_key_rotation_reminder_days: {
            name: 'Storage Account Key Rotation Reminder Days',
            description: 'Maximum number of days allowed for the storage account access key rotation reminder period',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            reminderDays: parseInt(settings.storage_account_key_rotation_reminder_days || this.settings.storage_account_key_rotation_reminder_days.default)
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
                if (!storageAccount.id) return;

                const reminderDays = storageAccount.keyPolicy ? storageAccount.keyPolicy.keyExpirationPeriodInDays : undefined;

                if (!reminderDays) {
                    helpers.addResult(results, 2,
                        'Storage Account does not have key rotation reminder enabled',
                        location, storageAccount.id);
                } else if (reminderDays <= config.reminderDays) {
                    helpers.addResult(results, 0,
                        `Storage Account key rotation reminder is set to ${reminderDays} days`,
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        `Storage Account key rotation reminder is set to ${reminderDays} days which is greater than ${config.reminderDays} days`,
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
