var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Compute Gallery RBAC Sharing',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that the Azure Compute Gallery is using RBAC only.',
    more_info: 'As the Azure Compute Gallery, definition, and version are all resources, they can be shared using the built-in native Azure Roles-based Access Control (RBAC) roles. A direct shared gallery can\'t contain encrypted image versions. Community galleries can be used by anyone with an Azure subscription making the resource more vulnerable.',
    recommended_action: 'Ensure that all Azure Compute Galleries are using RBAC only.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery',
    apis: ['computeGalleries:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.computeGalleries, function(location, rcb){

            var computeGalleries = helpers.addSource(cache, source, ['computeGalleries', 'list', location]);

            if (!computeGalleries) return rcb();

            if (computeGalleries.err || !computeGalleries.data) {
                helpers.addResult(results, 3, 'Unable to query for Compute Galleries' + helpers.addError(computeGalleries), location);
                return rcb();
            }
            if (!computeGalleries.data.length) {
                helpers.addResult(results, 0, 'No existing Compute Galleries found', location);
                return rcb();
            }

            computeGalleries.data.forEach(gallery => {
                if (gallery.sharingProfile && 
                    gallery.sharingProfile.permissions && 
                    (gallery.sharingProfile.permissions.toLowerCase() == 'community' ||
                    gallery.sharingProfile.permissions.toLowerCase() == 'groups')) {
                    helpers.addResult(results, 2, 'Compute Gallery does not have RBAC enabled', location, gallery.id);
                } else {
                    helpers.addResult(results, 0, 'Compute Gallery has RBAC enabled', location, gallery.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};