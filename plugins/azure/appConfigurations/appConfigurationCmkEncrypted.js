var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Configuration Encryption At Rest with CMK',
    category: 'App Configuration',
    domain: 'Developer Tools',
    severity: 'Medium',
    description: 'Ensures that Azure App Configuration stores are encrypted with CMK.',
    more_info: 'App Configuration encrypts sensitive information at rest by default using Azure managed key. The use of customer-managed keys provides enhanced data protection by allowing you to manage your encryption keys. When managed key encryption is used, all sensitive information in App Configuration is encrypted with a user-provided Azure Key Vault key.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-customer-managed-keys',
    recommended_action: 'Ensure that Azure App Configuration store has CMK encryption enabled.',
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

                if (appConfiguration.encryption && appConfiguration.encryption.keyVaultProperties && appConfiguration.encryption.keyVaultProperties.keyIdentifier) {
                    helpers.addResult(results, 0, 'App Configuration is encrypted using CMK', location, appConfiguration.id);
                } else {
                    helpers.addResult(results, 2, 'App Configuration is not encrypted using CMK', location, appConfiguration.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};