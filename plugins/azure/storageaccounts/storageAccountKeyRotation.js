const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Account Keys Rotated',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that Microsoft Azure Storage Account access keys are regenerated periodically.',
    more_info: 'Azure generates two access keys for each storage account which are used for authentication when the storage account is accessed. Regenerating these keys periodically ensures that inadvertent access or exposure does not result from the compromise of these keys.',
    recommended_action: 'Rotate the storage account access keys from the access keys settings of the storage account.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage',
    apis: ['storageAccounts:list'],
    settings: {
        storage_account_keys_rotation_days: {
            name: 'Storage Account Keys Rotation Days',
            description: 'Maximum number of days allowed since the storage account access keys were last rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftstorage:storageaccounts:regeneratekey'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            rotationDays: parseInt(settings.storage_account_keys_rotation_days || this.settings.storage_account_keys_rotation_days.default)
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

                const keyCreationTime = storageAccount.keyCreationTime;

                if (!keyCreationTime || (!keyCreationTime.key1 && !keyCreationTime.key2)) {
                    helpers.addResult(results, 2,
                        'Storage Account access keys have never been rotated',
                        location, storageAccount.id);
                    return;
                }

                const keyAges = ['key1', 'key2'].filter(key => keyCreationTime[key])
                    .map(key => helpers.daysBetween(new Date(), new Date(keyCreationTime[key])));
                const oldestKeyAge = Math.max(...keyAges);

                if (oldestKeyAge <= config.rotationDays) {
                    helpers.addResult(results, 0,
                        `Storage Account access keys were last rotated ${oldestKeyAge} days ago which is equal to or less than ${config.rotationDays} days limit`,
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        `Storage Account access keys were last rotated ${oldestKeyAge} days ago which is more than ${config.rotationDays} days limit`,
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
