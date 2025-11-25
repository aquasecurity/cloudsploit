var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configuration Access Key Authentication Disabled',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'Low',
    description: 'Ensures that access key authentication is disabled for App Configuration.',
    more_info: 'By default, requests can be authenticated with either Microsoft Entra credentials, or by using an access key. For enhanced security, centralized identity management, and seamless integration with Azure\'s authentication and authorization services, it is recommended to rely on Azure Entra ID and disable local authentication for Azure App Configurations.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-app-configuration/howto-disable-access-key-authentication',
    recommended_action: 'Ensure that Azure App Configurations have access key authentication disabled.',
    apis: ['appConfigurations:list'],
    realtime_triggers: ['microsoftappconfiguration:configurationstores:write','microsoftappconfiguration:configurationstores:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.appConfigurations, function(location, rcb){
            var appConfigurations = helpers.addSource(cache, source,
                ['appConfigurations', 'list', location]);

            if (!appConfigurations) return rcb();

            if (appConfigurations.err || !appConfigurations.data) {
                helpers.addResult(results, 3, 'Unable to query App Configuration: ' + helpers.addError(appConfigurations), location);
                return rcb();
            }

            if (!appConfigurations.data.length) {
                helpers.addResult(results, 0, 'No existing App Configurations found', location);
                return rcb();
            }

            for (let appConfiguration of appConfigurations.data) {
                if (!appConfiguration.id) continue;

                if (appConfiguration.disableLocalAuth){                    
                    helpers.addResult(results, 0, 'App Configuration has access key authentication disabled', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration does not have access key authentication disabled', location, appConfiguration.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
