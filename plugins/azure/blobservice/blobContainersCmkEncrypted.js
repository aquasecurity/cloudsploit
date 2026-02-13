var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Blob Container CMK Encrypted',
    category: 'Blob Service',
    domain: 'Storage',
    description: 'Ensures that blob containers in storage account are CMK encrypted',
    severity: 'High',
    more_info: 'Azure allows you to encrypt data in your blob containers using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Configuring a customer-managed key for blob services ensures protection and control access to the key that encrypts your data. Customer-managed keys offer greater flexibility to manage access controls.',
    recommended_action: 'Ensure that all blob containers in storage account store has CMK encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview',
    apis: ['storageAccounts:list', 'blobContainers:list', 'encryptionScopes:listByStorageAccounts'],
    realtime_triggers: ['microsoftstorage:storageaccounts:blobservices:containers:write', 'microsoftstorage:storageaccounts:blobservices:containers:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        async.each(locations.storageAccounts, (location, rcb) => {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]
            );

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(
                    results, 0, 'No existing Storage Accounts found', location);
                return rcb();
            }

            for (var storageAccount of storageAccounts.data) {
                const blobContainers = helpers.addSource(
                    cache, source, ['blobContainers', 'list', location, storageAccount.id]
                );

                if (!blobContainers || blobContainers.err || !blobContainers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Blob Containers: ' + helpers.addError(blobContainers),
                        location, storageAccount.id);
                } else if (!blobContainers.data.length) {
                    helpers.addResult(results, 0, 'Storage Account does not contain blob containers', location, storageAccount.id);
                } else {
                    var accountLevelCMK =
                        storageAccount.encryption &&
                        storageAccount.encryption.keySource &&
                        storageAccount.encryption.keySource.toLowerCase() === 'microsoft.keyvault';

                    const encryptionScopes = helpers.addSource(
                        cache, source, ['encryptionScopes', 'listByStorageAccounts', location, storageAccount.id]);

                    if (!encryptionScopes || encryptionScopes.err || !encryptionScopes.data) {
                        helpers.addResult(results, 3,
                            'Unable to query encryption scopes for Storage Accounts: ' + helpers.addError(encryptionScopes),
                            location, storageAccount.id);
                    } else {
                        var cmkEncryptionScopes = encryptionScopes.data.filter(function(scope) {
                            return scope.keyVaultProperties && scope.keyVaultProperties.keyUri;
                        }).map(function(scope) {
                            return scope.name;
                        });

                        blobContainers.data.forEach(function(blob) {
                            if (blob.defaultEncryptionScope && cmkEncryptionScopes.includes(blob.defaultEncryptionScope)) {
                                helpers.addResult(results, 0, 'Blob container has CMK encryption enabled via container-level encryption scope', location, blob.id);
                            } else if (accountLevelCMK) {
                                helpers.addResult(results, 0, 'Blob container has CMK encryption enabled via storage account-level configuration', location, blob.id);
                            } else {
                                helpers.addResult(results, 2, 'Blob container does not have CMK encryption enabled', location, blob.id);
                            }
                        });
                    }

                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};