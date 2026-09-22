const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Soft Deletion Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that soft delete feature is enabled for all Microsoft Storage Account containers.',
    more_info: 'When soft delete for containers is enabled for a storage account, deleted containers may be recovered after they are deleted, within a retention period that you specify.',
    recommended_action: 'Enable soft delete for containers and set deletion retention policy to keep containers for more than desired number of days',
    link: 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview',
    apis: ['storageAccounts:list', 'blobServices:getServiceProperties'],
    settings: {
        keep_deleted_containers_for_days: {
            name: 'Keep Deleted Containers for Days',
            description: 'Number of days that a container is marked for deletion persists until it is permanently deleted',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '7'
        }
    },
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftstorage:storageaccounts:blobservices:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            keepForDays: parseInt(settings.keep_deleted_containers_for_days || this.settings.keep_deleted_containers_for_days.default)
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
                    ['blobServices', 'getServiceProperties', location, storageAccount.id]);

                if (!getServiceProperties || getServiceProperties.err || !getServiceProperties.data) {
                    helpers.addResult(results, 3,
                        `Unable to get blob service properties: ${helpers.addError(getServiceProperties)}`,
                        location, storageAccount.id);
                } else {
                    if (getServiceProperties.data.containerDeleteRetentionPolicy &&
                        getServiceProperties.data.containerDeleteRetentionPolicy.enabled &&
                        getServiceProperties.data.containerDeleteRetentionPolicy.days) {
                        const retentionDays = getServiceProperties.data.containerDeleteRetentionPolicy.days;

                        if (retentionDays >= config.keepForDays) {
                            helpers.addResult(results, 0,
                                `Containers deletion policy is configured to persist deleted containers for ${retentionDays} of ${config.keepForDays} days desired limit`,
                                location, storageAccount.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Containers deletion policy is configured to persist deleted containers for ${retentionDays} of ${config.keepForDays} days desired limit`,
                                location, storageAccount.id);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'Containers soft delete feature is not enabled for Storage Account',
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
