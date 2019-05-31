const async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
  title: 'Blob Container Private Access',
  category: 'Blob Service',
  description: 'Ensure that all blob containers do not have anonymous public access level.',
  more_info: 'Blob containers set with public access, enables anonymous users to read blobs within a publicly accessible container without authenticating the request. Ensure that private access is set to all of blob containers.',
  recommended_action: 'Create blob container with public access level.',
  link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction',
  apis: ['storageAccounts:list', 'blobContainers:list', 'resources:list'],

  run: function (cache, settings, callback) {
    const results = [];
    const source = {};
    const locations = helpers.locations(settings.govcloud);

    function sqlResourceExists(resourceList) {
      return JSON.stringify(resourceList).indexOf('Microsoft.Storage/storageAccounts') > -1
    }

    async.each(locations.blobContainers, (location, rcb) => {
      const blobContainers = helpers.addSource(cache, source, ['blobContainers', 'list', location]);

      const resourceList = helpers.addSource(cache, source, ['resources', 'list', location]);

      if (sqlResourceExists(resourceList)) {

        if(!blobContainers) return rcb();

        if (blobContainers.err || !blobContainers.data) {
          helpers.addResult(results, 3,
              'Unable to query for blob containers: ' + helpers.addError(blobContainers), location);
          return rcb();
        } else if (!blobContainers.data.length) {
          helpers.addResult(results, 0, 'No blob containers to check', location);
          return rcb();
        }

        let publicAccess = false;
        let blobContainerFound = false;

        for (let data of blobContainers.data) {
          for (let containerItem of data.value) {
            blobContainerFound = true;
            if (containerItem.publicAccess != "None") {
              helpers.addResult(results, 2, 'Blob container ' + containerItem.id + ' allows public access', location);
              publicAccess = true;
            }
          }
        }

        if (!blobContainerFound) {
          helpers.addResult(results, 0, 'No blob containers to check', location);
        } else if (!publicAccess) {
          helpers.addResult(results, 0, 'There are no blob containers with public access level', location);
        }

      } else {
        helpers.addResult(results, 0, 'No Storage Account Resources found, ignoring monitoring requirement', location);
      }

      rcb();
    }, function () {
      callback(null, results, source);
    });
  }
};
