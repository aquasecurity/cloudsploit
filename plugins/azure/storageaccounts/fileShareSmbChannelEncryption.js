const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Share SMB Channel Encryption',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that SMB file shares are configured to only allow AES-256-GCM or higher for SMB channel encryption.',
    more_info: 'Weaker SMB channel encryption algorithms such as AES-128-CCM and AES-128-GCM offer less protection against eavesdropping and man-in-the-middle attacks. Restricting SMB file shares to AES-256-GCM only helps ensure data confidentiality and integrity in transit.',
    recommended_action: 'Modify the SMB security settings for the storage account file service and allow only AES-256-GCM for channel encryption.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/files/files-smb-protocol',
    apis: ['storageAccounts:list', 'fileServices:getServiceProperties'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftstorage:storageaccounts:fileservices:write'],

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
                const getServiceProperties = helpers.addSource(cache, source,
                    ['fileServices', 'getServiceProperties', location, storageAccount.id]);

                if (!getServiceProperties || getServiceProperties.err || !getServiceProperties.data) {
                    helpers.addResult(results, 3,
                        `Unable to get file service properties: ${helpers.addError(getServiceProperties)}`,
                        location, storageAccount.id);
                } else {
                    const channelEncryption = getServiceProperties.data.protocolSettings &&
                        getServiceProperties.data.protocolSettings.smb &&
                        getServiceProperties.data.protocolSettings.smb.channelEncryption;

                    const encryptionList = channelEncryption ?
                        channelEncryption.split(';').map(algorithm => algorithm.trim()).filter(algorithm => algorithm) : [];

                    if (encryptionList.length && encryptionList.every(algorithm => algorithm.toUpperCase() === 'AES-256-GCM')) {
                        helpers.addResult(results, 0,
                            `File share SMB channel encryption is set to ${encryptionList.join(', ')}`,
                            location, storageAccount.id);
                    } else {
                        helpers.addResult(results, 2,
                            `File share SMB channel encryption is set to ${encryptionList.length ? encryptionList.join(', ') : 'all SMB channel encryption algorithms'} instead of AES-256-GCM only`,
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
