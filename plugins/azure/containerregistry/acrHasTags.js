const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Has Tags',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensure that Microsoft Azure Container registries have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Container registries and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['registries:list'],
    realtime_triggers: ['microsoftcontainerregistry:registries:write','microsoftcontainerregistry:registries:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.registries, (location, rcb) => {
            var conatinerRegisteries = helpers.addSource(cache, source, 
                ['registries', 'list', location]);

            if (!conatinerRegisteries) return rcb();

            if (conatinerRegisteries.err || !conatinerRegisteries.data) {
                helpers.addResult(results, 3, 'Unable to query for Container registries: ' + helpers.addError(conatinerRegisteries), location);
                return rcb();
            }

            if (!conatinerRegisteries.data.length) {
                helpers.addResult(results, 0, 'No existing Container registries found', location);
                return rcb();
            } 
            
            for (let registry of conatinerRegisteries.data) {
                if (!registry.id) continue;

                if (registry.tags && Object.entries(registry.tags).length > 0){
                    helpers.addResult(results, 0, 'Conatiner Registry has tags associated', location, registry.id);
                } else {
                    helpers.addResult(results, 2, 'Conatiner Registry does not have tags associated', location, registry.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
