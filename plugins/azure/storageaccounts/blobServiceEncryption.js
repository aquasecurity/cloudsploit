const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Blob Service Encryption',
    category: 'Storage Accounts',
    description: 'Ensures encryption is properly configured in Blob Services to protect data-at-rest and meet compliance requirements.',
    more_info: 'Blob Services can be configured to encrypt data-at-rest, by default Azure will create a set of keys to encrypt your Blob Services, but the recommended approach is to create your own keys using Azure Key Vault.',
    recommended_action: '1. Go to your Storage Account. 2. Enter the Blob Service 3. Select Encryption, and check the box to use your own key, then select Key Vault, create a new vault if needed; then select Encryption key and create a new key if needed, at a minimum, set an activation date for your key to help with your key rotation policy, click Save when done.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption',
    apis: ['storageAccounts:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'Enabling encryption of storage account data helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
             'Encryption should be enabled for all storage accounts storing this ' +
             'type of data.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function (location, rcb) {
            const storageAccounts = helpers.addSource(
                cache, source, ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3, 
                    'Unable to query for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            };

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            };

            storageAccounts.data.forEach(storageAccount => {
                if (storageAccount.encryption && 
                   storageAccount.encryption.services &&  
                   storageAccount.encryption.services.blob &&  
                   storageAccount.encryption.services.blob.enabled) {
                    helpers.addResult(results, 0, 'Blob encryption is enabled', location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Blob encryption is not enabled', location, storageAccount.id);
                };
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
