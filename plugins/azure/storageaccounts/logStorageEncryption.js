var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Log Storage Encryption',
    category: 'Storage Accounts',
    description: 'Ensures BYOK encryption is properly configured in the Activity Log Storage Account',
    more_info: 'Storage accounts can be configured to encrypt data-at-rest. By default Azure will create a set of keys to encrypt the storage account, but the recommended approach is to create your own keys using Azure Key Vault.',
    recommended_action: 'Ensure the Storage Account used by Activity Logs is configured with a BYOK key.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption-customer-managed-keys',
    apis: ['storageAccounts:list', 'logProfiles:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'Enabling encryption of log storage data helps to protect this data.',
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var logProfile;

        for (var location of locations.logProfiles) {

            const logProfiles = helpers.addSource(cache, source,
                ['logProfiles', 'list', location]);

            if (!logProfiles) continue;

            if (logProfiles.err || !logProfiles.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Log Profiles: ' + helpers.addError(logProfiles), location);
                continue;
            }

            if (!logProfiles.data.length) {
                continue;
            } else {
                logProfile = logProfiles.data[0];
                break;
            }
        }

        if (!logProfile) {
            helpers.addResult(results, 2,
                'No Log Profile enabled', 'global');
        } else {
            helpers.addResult(results, 0,
                'Log Profile is enabled', 'global', logProfile.id);
        }

        async.each(locations.storageAccounts, (loc, cb) => {

            const storageAccounts = helpers.addSource(cache, source,
                    ['storageAccounts', 'list', loc]);

            if (!storageAccounts) return cb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccounts), loc);
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No existing Storage Accounts found', loc);
                return cb();
            }

            storageAccounts.data.forEach(storageAccount => {
                if (storageAccount.encryption &&
                    storageAccount.encryption.keySource &&
                    storageAccount.encryption.keySource != 'Microsoft.Keyvault' &&
                    !storageAccount.encryption.keyVaultProperties) {
                    helpers.addResult(results, 2,
                        'Activity Logs container for the storage account is not encrypted with BYOK', loc, storageAccount.id);
                } else {
                    helpers.addResult(results, 0,
                        'Activity Logs container for the storage account is encrypted with BYOK', loc, storageAccount.id);
                }
            });
            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};