const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Route Table Has Tags',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensures that Microsoft Azure Network route tables have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify route tables and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['routeTables:listAll'],
    realtime_triggers: ['microsoftnetwork:routetables:write','microsoftnetwork:routetables:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.routeTables, (location, rcb) => {
            var routeTables = helpers.addSource(cache, source, 
                ['routeTables', 'listAll', location]);
                
            if (!routeTables) return rcb();

            if (routeTables.err || !routeTables.data) {
                helpers.addResult(results, 3, 'Unable to query for route tables: ' + helpers.addError(routeTables), location);
                return rcb();
            }

            if (!routeTables.data.length) {
                helpers.addResult(results, 0, 'No existing Route table found', location);
                return rcb();
            } 
            
            for (let routeTable of routeTables.data) {
                if (!routeTable.id) continue;

                if (routeTable.tags && Object.entries(routeTable.tags).length > 0){
                    helpers.addResult(results, 0, 'Route table has tags associated', location, routeTable.id);
                } else {
                    helpers.addResult(results, 2, 'Route table does not have tags associated', location, routeTable.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
