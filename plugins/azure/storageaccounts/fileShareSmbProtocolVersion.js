const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'File Share SMB Protocol Version',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensures that SMB file shares are configured to only allow SMB 3.1.1 or higher.',
    more_info: 'Older SMB protocol versions such as SMB 2.1 and SMB 3.0 may contain known vulnerabilities and lack modern security controls. Restricting SMB file shares to SMB 3.1.1 only helps mitigate the risk of exploitation.',
    recommended_action: 'Modify the SMB security settings for the storage account file service and allow only SMB 3.1.1.',
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
                    const smbVersions = getServiceProperties.data.protocolSettings &&
                        getServiceProperties.data.protocolSettings.smb &&
                        getServiceProperties.data.protocolSettings.smb.versions;

                    const versionList = smbVersions ?
                        smbVersions.split(';').map(version => version.trim()).filter(version => version) : [];

                    if (versionList.length && versionList.every(version => version.toUpperCase() === 'SMB3.1.1')) {
                        helpers.addResult(results, 0,
                            `File share SMB protocol version is set to ${versionList.join(', ')}`,
                            location, storageAccount.id);
                    } else {
                        helpers.addResult(results, 2,
                            `File share SMB protocol version is set to ${versionList.length ? versionList.join(', ') : 'all SMB versions'} instead of SMB3.1.1 only`,
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
