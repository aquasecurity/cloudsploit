var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configurations Has Tags',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'Low',
    description: 'Ensures that Azure App Configurations has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify app configurations and add tags.',
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

                if (appConfiguration.tags && Object.entries(appConfiguration.tags).length > 0){                    
                    helpers.addResult(results, 0, 'App Configuration has tags associated', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration does not have tags associated', location, appConfiguration.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
