const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Container Public Access',
    category: 'Storage Accounts',
    description: 'Ensure that the Activity Log Container does not have public read access.',
    more_info: 'Enabling private access only on the Activity Log Storage Container ensures that log data is secured and only accessible from within, following security best practices.',
    recommended_action: '1. Enter the activity log service. 2. Choose the export option. 3. Note the storage container in use. 4. Enter the storage account in use by navigating to the storage accounts service. 5. Select the Blob blade under Blob Service. 6. Select insights-operational-logs. 7. Click on Access Level and ensure that access is set to private.',
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
                    'Unable to query Storage Containers: ' + helpers.addError(blobContainerList), loc);
                return cb();
            }

            if (!blobContainerList.data.length) {
                helpers.addResult(results, 0, 'No existing Storage Containers', loc);
                return cb();
            }

            blobContainerList.data.forEach(blobContainers => {
                blobContainers.value.forEach(blobContainer => {
                    if (blobContainer.name === "insights-operational-logs" &&
                        blobContainer.publicAccess !== "None") {
                        helpers.addResult(results, 2,
                            'Storage container storing the activity logs is publicly accessible.', loc, blobContainers.storageAccount.name);
                        containerExists = true;
                    } else if (
                        blobContainer.name === "insights-operational-logs" &&
                        blobContainer.publicAccess == "None") {
                        helpers.addResult(results, 0,
                            'Storage container storing the activity logs is not publicly accessible.', loc, blobContainers.storageAccount.name);
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
