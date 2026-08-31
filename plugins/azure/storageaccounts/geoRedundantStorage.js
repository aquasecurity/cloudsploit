const async = require('async');
const helpers = require('../../../helpers/azure');

const GEO_REDUNDANT_SKUS = ['standard_grs', 'standard_ragrs', 'standard_gzrs', 'standard_ragzrs'];

module.exports = {
    title: 'Storage Account Geo-Redundancy',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that geo-redundant storage is configured for Microsoft Azure Storage Accounts.',
    more_info: 'Geo-redundant storage replicates data to a secondary region hundreds of miles away from the primary region, providing 16 nines of durability and protecting data against a complete regional outage. Locally redundant and zone-redundant storage only replicate within the primary region and do not protect against regional disasters.',
    recommended_action: 'Modify the redundancy setting of the storage account and select a geo-redundant option such as geo-redundant storage (GRS).',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy',
    apis: ['storageAccounts:list'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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

                const skuName = storageAccount.sku ? storageAccount.sku.name : undefined;

                if (!skuName) {
                    helpers.addResult(results, 3,
                        'Unable to determine Storage Account redundancy setting',
                        location, storageAccount.id);
                } else if (GEO_REDUNDANT_SKUS.includes(skuName.toLowerCase())) {
                    helpers.addResult(results, 0,
                        `Storage Account redundancy is set to ${skuName} which is geo-redundant`,
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        `Storage Account redundancy is set to ${skuName} which is not geo-redundant`,
                        location, storageAccount.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
