var async = require('async');

var helpers = require('../../../helpers/azure');


module.exports = {
    title: 'VM Scale Set Has Tags',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Azure Virtual Machine scale sets have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify VM scale set and add tags.',
    apis: ['vmScaleSet:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachinescalesets:write', 'microsoftcompute:virtualmachinescalesets:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vmScaleSet, function(location, rcb) {

            var vmScaleSets = helpers.addSource(cache, source, ['vmScaleSet', 'listAll', location]);

            if (!vmScaleSets) return rcb();

            if (vmScaleSets.err || !vmScaleSets.data) {
                helpers.addResult(results, 3, 'Unable to query for VM scale sets: ' + helpers.addError(vmScaleSets), location);
                return rcb();
            }
            if (!vmScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing VM scale sets found', location);
                return rcb();
            }
            for (let set of vmScaleSets.data) {
                if (!set.id) continue;

                if (set.tags && Object.entries(set.tags).length > 0){
                    helpers.addResult(results, 0, 'VM scale set has tags', location, set.id);
                } else {
                    helpers.addResult(results, 2, 'VM scale set does not have tags', location, set.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};