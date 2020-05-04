const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Container Public Access',
    category: 'Storage Accounts',
    description: 'Ensures that the Activity Log Container does not have public read access',
    more_info: 'The container used to store Activity Log data should not be exposed publicly to avoid data exposure of sensitive activity logs.',
    recommended_action: 'Ensure the access level for the storage account containing Activity Log data is set to private.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-manage-access-to-resources',
    apis: ['storageAccounts:list', 'blobContainers:list', 'diagnosticSettingsOperations:list'],
    compliance: {
        hipaa: 'HIPAA requires that all systems used for storing ' +
                'covered and user data must deny-all activity by ' +
                'default, along with keeping all data private ' +
                'and secure.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let containerExists = false;
        var diagnosticContainers = {};
        var diagnosticSettingsOperations = helpers.addSource(cache, source,
            ['diagnosticSettingsOperations', 'list', 'global']);

        if (!diagnosticSettingsOperations || diagnosticSettingsOperations.err || !diagnosticSettingsOperations.data) {
            diagnosticSettingsOperations.data = [];
        }

        if (diagnosticSettingsOperations.data.length) {
            diagnosticSettingsOperations.data.forEach(diagnosticSettingsOperation => {
                if (!diagnosticContainers[diagnosticSettingsOperation.storageAccountId]) diagnosticContainers[diagnosticSettingsOperation.storageAccountId] = [];
                diagnosticContainers[diagnosticSettingsOperation.storageAccountId].push(diagnosticSettingsOperation.name)
            })
        }

        async.each(locations.blobContainers, (loc, cb) => {
            const blobContainerList = helpers.addSource(cache, source,
                ['blobContainers', 'list', loc]);

            if (!blobContainerList) return cb();

            if (blobContainerList.err || !blobContainerList.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Containers: ' + helpers.addError(blobContainerList), loc);
                return cb();
            }

            if (!blobContainerList.data.length) {
                helpers.addResult(results, 0, 'No existing Storage Containers found', loc);
                return cb();
            }

            blobContainerList.data.forEach(blobContainers => {
                var diagnosticBlob = [];
                if (blobContainers.id && diagnosticContainers[blobContainers.id] && diagnosticContainers[blobContainers.id].length) {
                    diagnosticBlob = diagnosticContainers[blobContainers.id];
                }
                blobContainers.value.forEach(blobContainer => {
                    if (blobContainer.name &&
                        ((diagnosticBlob.indexOf(blobContainer.name) > -1) ||
                        (blobContainer.name.toLowerCase() === "insights-operational-logs") ||
                        (blobContainer.name.toLowerCase().indexOf("insights-logs-") > -1)) &&
                        blobContainer.publicAccess) {
                        if (blobContainer.publicAccess.toLowerCase() === "none") {
                            helpers.addResult(results, 0,
                                'Storage container storing the activity logs is not publicly accessible', loc, blobContainer.id);
                            containerExists = true;
                        } else {
                            helpers.addResult(results, 2,
                                'Storage container storing the activity logs is publicly accessible', loc, blobContainer.id);
                            containerExists = true;
                        }
                    }
                });
            });

            if (!containerExists) {
                helpers.addResult(results, 0,
                    'No existing Storage Containers found for insight logs', loc);
            }

            cb();
        }, function () {
            callback(null, results, source);
        });
    }
};
