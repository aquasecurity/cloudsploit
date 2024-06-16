var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'API Management Instance Managed Identity',
    category: 'API Management',
    domain: 'Developer Tools',
    severity: 'Medium',
    description: 'Ensures that Azure API Management instance has managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    link: 'https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-use-managed-service-identity',
    recommended_action: 'Modify API Management instance and add managed identity.',
    apis: ['apiManagementService:list'],
    realtime_triggers: ['microsoftapimanagement:service:write','microsoftapimanagement:service:delete'],

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

                if (apiInstance.identity) {
                    helpers.addResult(results, 0, 'API Management service instance has managed identity enabled', location, apiInstance.id);
                } else {
                    helpers.addResult(results, 2, 'API Management service instance does not have managed identity enabled', location, apiInstance.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
