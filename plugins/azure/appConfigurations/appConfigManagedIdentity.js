var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configurations Managed Identity',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'Medium',
    description: 'Ensures that Azure App Configurations have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Entra ID tokens.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-app-configuration/overview-managed-identity',
    recommended_action: 'Modify App Configuration store and add managed identity.',
    apis: ['appConfigurations:list'],
    realtime_triggers: ['microsoftappconfiguration:configurationstores:write','microsoftappconfiguration:configurationstores:delete'],

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

                if (appConfiguration.identity) {
                    helpers.addResult(results, 0, 'App Configuration has managed identity enabled', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration does not have managed identity enabled', location, appConfiguration.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
