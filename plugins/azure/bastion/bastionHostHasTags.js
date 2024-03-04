var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Bastion Host Has Tags',
    category: 'Bastion',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that Azure Bastion host has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Bastion host and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['bastionHosts:listAll'],
    realtime_triggers: ['microsoftnetwork:bastionhosts:write','microsoftnetwork:bastionhosts:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.bastionHosts, function(location, rcb){
            let bastionHost = helpers.addSource(cache, source, 
                ['bastionHosts', 'listAll', location]);

            if (!bastionHost) return rcb();

            if (bastionHost.err || !bastionHost.data) {
                helpers.addResult(results, 3, 'Unable to query for Bastion Host: ' + helpers.addError(bastionHost), location);
                return rcb();
            }

            if (!bastionHost.data.length) {
                helpers.addResult(results, 0, 'No existing Bastion hosts found', location);
                return rcb();
            }
            for (let host of bastionHost.data) {
                if (!host.id) continue;

                if (host.tags && Object.entries(host.tags).length > 0) {
                    helpers.addResult(results, 0, 'Bastion Host has tags', location, host.id);
                } else {
                    helpers.addResult(results, 2, 'Bastion Host does not have tags', location, host.id);
                }
            }
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 