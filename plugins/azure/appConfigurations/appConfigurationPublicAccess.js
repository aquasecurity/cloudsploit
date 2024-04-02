var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configurations Public Access',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'High',
    description: 'Ensures that Azure App Configurations have public access disabled.',
    more_info: 'Disabling public network access improves security by ensuring that the app configuration isn\'t exposed on the public internet. Limit exposure of your resources by creating private endpoints instead.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-app-configuration/howto-disable-public-access?tabs=azure-portal',
    recommended_action: 'Modify App Configuration and disable public access.',
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

                if (appConfiguration.publicNetworkAccess && appConfiguration.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0, 'App Configuration has public network access disabled', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration does not have public network access disabled', location, appConfiguration.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
