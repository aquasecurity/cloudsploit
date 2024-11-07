var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VM Image Has Tags',
    category: 'Virtual Machines',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensures that Microsoft Azure virtual machine images have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify virtual machine image and add tags',
    apis: ['images:list'],
    realtime_triggers: ['microsoftcompute:images:write', 'microsoftcompute:images:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.images, function(location, rcb) {
            const snapshots = helpers.addSource(cache, source,
                ['images', 'list', location]);

            if (!snapshots) return rcb();

            if (snapshots.err || !snapshots.data) {
                helpers.addResult(results, 3, 'Unable to query for virtual machine image :' + helpers.addError(snapshots), location);
                return rcb();
            }

            if (!snapshots.data.length) {
                helpers.addResult(results, 0, 'No virtual machine image found', location);
                return rcb();
            }
            for (let image of snapshots.data){
                if (!image.id) continue;

                if (image.tags && Object.entries(image.tags).length > 0){
                    helpers.addResult(results, 0, 'VM Image has tags associated', location, image.id);
                } else {
                    helpers.addResult(results, 2, 'VM Image does not have tags associated', location, image.id);
                } 
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
 