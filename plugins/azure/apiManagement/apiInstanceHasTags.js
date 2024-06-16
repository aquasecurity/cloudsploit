var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'API Management Instance Has Tags',
    category: 'API Management',
    domain: 'Developer Tools',
    severity: 'Medium',
    description: 'Ensures that Azure API Management instance has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify API Management instance and add tags.',
    apis: ['apiManagementService:list'],
    realtime_triggers: ['microsoftapimanagement:service:write','microsoftapimanagement:service:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.apiManagementService, function(location, rcb){
            var apiManagementService = helpers.addSource(cache, source,
                ['apiManagementService', 'list', location]);

            if (!apiManagementService) return rcb();

            if (apiManagementService.err || !apiManagementService.data) {
                helpers.addResult(results, 3, 'Unable to query API Management instances:' + helpers.addError(apiManagementService), location);
                return rcb();
            }

            if (!apiManagementService.data.length) {
                helpers.addResult(results, 0, 'No existing API Management instances found', location);
                return rcb();
            }

            for (let apiInstance of apiManagementService.data) {
                if (!apiInstance.id) continue;

                if (apiInstance.tags && Object.entries(apiInstance.tags).length > 0) {
                    helpers.addResult(results, 0, 'API Management instance has tags associated', location, apiInstance.id);
                } else {
                    helpers.addResult(results, 2, 'API Management instance does not have tags associated', location, apiInstance.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
