const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Virtual Network Has Tags',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    description: 'Ensures that Microsoft Azure Virtual Network has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify virtual networks and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['virtualNetworks:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, (location, rcb) => {
            var virtualNetworks = helpers.addSource(cache, source, 
                ['virtualNetworks', 'listAll', location]);

            if (!virtualNetworks) return rcb();

            if (virtualNetworks.err || !virtualNetworks.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Networks: ' + helpers.addError(virtualNetworks), location);
                return rcb();
            }

            if (!virtualNetworks.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Networks found', location);
                return rcb();
            } 
            
            for (let virtualNetwork of virtualNetworks.data) {
                if (!virtualNetwork.id) continue;

                if (virtualNetwork.tags && Object.entries(virtualNetwork.tags).length > 0){
                    helpers.addResult(results, 0, 'Virtual Network has tags associated', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Network does not have tags associated', location, virtualNetwork.id);
                } 

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
