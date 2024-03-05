var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Resource Group Has Tags',
    category: 'Resource Group',
    domain: 'Management',
    severity: 'Low',
    description: 'Ensures that Azure resource groups have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify affected resource group and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources-portal',
    apis: ['resourceGroups:list'],
    realtime_triggers: ['microsoftresources:subscriptions:resourcegroups:write','microsoftresources:subscriptions:resourcegroups:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.resourceGroups, function(location, rcb){

            var resourceGroups = helpers.addSource(cache, source,
                ['resourceGroups', 'list', location]);

            if (!resourceGroups) return rcb();

            if (resourceGroups.err || !resourceGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for resource groups: ' + helpers.addError(resourceGroups), location);
                return rcb();
            }
            if (!resourceGroups.data.length) {
                helpers.addResult(results, 0, 'No existing resource groups found', location);
                return rcb();
            }
            for (let rg of resourceGroups.data) { 
                if (!rg.id) continue;
                
                if (rg.tags && Object.keys(rg.tags).length > 0) {
                    helpers.addResult(results, 0, 'Resource group has tags', location, rg.id);
                } else {
                    helpers.addResult(results, 2, 'Resource group does not have tags', location, rg.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};