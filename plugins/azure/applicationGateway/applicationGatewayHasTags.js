const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway Has Tags',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensures that Microsoft Azure Application Gateway has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify application gateways and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['applicationGateway:listAll'],
    realtime_triggers: ['microsoftnetwork:applicationgateways:write','microsoftnetwork:applicationgateways:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.applicationGateway, (location, rcb) => {
            var appGateways = helpers.addSource(cache, source,
                ['applicationGateway', 'listAll', location]);

            if (!appGateways) return rcb();

            if (appGateways.err || !appGateways.data) {
                helpers.addResult(results, 3, 'Unable to query for application gateways: ' + helpers.addError(appGateways), location);
                return rcb();
            }

            if (!appGateways.data.length) {
                helpers.addResult(results, 0, 'No existing application gateways found', location);
                return rcb();
            }

            for (let appGateway of appGateways.data) {
                if (!appGateway.id) continue;

                if (appGateway.tags && Object.entries(appGateway.tags).length > 0){
                    helpers.addResult(results, 0, 'Application Gateway has tags associated', location, appGateway.id);
                } else {
                    helpers.addResult(results, 2, 'Application Gateway does not have tags associated', location, appGateway.id);
                }

            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
