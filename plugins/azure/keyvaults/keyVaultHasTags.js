var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Has Tags',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensure that Azure Key Vault vaults have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify key vault and tags',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            for (let vault of vaults.data) {
                if (vault.tags && Object.entries(vault.tags).length > 0){
                    helpers.addResult(results, 0, 'Key Vault has tags associated', location, vault.id);
                } else {
                    helpers.addResult(results, 2, 'Key Vault does not have tags associated', location, vault.id);
                } 
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};