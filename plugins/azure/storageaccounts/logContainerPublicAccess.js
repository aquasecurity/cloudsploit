const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Container Public Access',
    category: 'Storage Accounts',
    description: 'Ensures that the Activity Log Container does not have public read access',
    more_info: 'The container used to store Activity Log data should not be exposed publicly to avoid data exposure of sensitive activity logs.',
    recommended_action: 'Ensure the access level for the storage account containing Activity Log data is set to private.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-manage-access-to-resources',
    apis: ['storageAccounts:list', 'blobContainers:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        let containerExists = false;

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
                blobContainers.value.forEach(blobContainer => {
                    if (blobContainer.name === "insights-operational-logs" &&
                        blobContainer.publicAccess !== "None") {
                        helpers.addResult(results, 2,
                            'Storage container storing the activity logs is publicly accessible', loc, blobContainers.id);
                        containerExists = true;
                    } else if (
                        blobContainer.name === "insights-operational-logs" &&
                        blobContainer.publicAccess == "None") {
                        helpers.addResult(results, 0,
                            'Storage container storing the activity logs is not publicly accessible', loc, blobContainers.id);
                        containerExists = true;
                    }
                });
            });

            cb();
        }, function () {

            if (!containerExists){
                helpers.addResult(results, 2,
                    'There are no Storage containers storing the activity logs.', 'global');
            }

            callback(null, results, source);
        });
    }
};
