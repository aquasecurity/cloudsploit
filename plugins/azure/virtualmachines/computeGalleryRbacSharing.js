var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Compute Gallery RBAC Sharing',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that the Azure Compute Gallery machine images are shared using RBAC only.',
    more_info: 'Images, definitions, and versions in Azure Compute Gallery can be shared using the built-in Azure Roles-based Access Control (RBAC) roles. Compute Galleries shared directly with subscription, tenant or community expose the resource to increased vulnerability. Directly shared galleries cannot contain encrypted image versions.',
    recommended_action: 'Ensure that all Azure Compute Galleries are using RBAC only.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries?tabs=azure-cli#sharing',
    apis: ['computeGalleries:list'],
    realtime_triggers: ['microsoftcompute:galleries:write', 'microsoftcompute:galleries:delete', 'microsoftcompute:galleries:share:action'],

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

                if (!gallery.sharingProfile || (gallery.sharingProfile && gallery.sharingProfile.permissions && gallery.sharingProfile.permissions.toLowerCase() == 'private')) {
                    helpers.addResult(results, 0, 'Compute Gallery machine images are shared using RBAC only', location, gallery.id);
                } else {
                    helpers.addResult(results, 2, `Compute Gallery machine images are shared with ${gallery.sharingProfile.permissions.toLowerCase()}`, location, gallery.id);
                }

            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};