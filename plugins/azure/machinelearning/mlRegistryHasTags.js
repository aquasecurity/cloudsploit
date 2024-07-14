var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Registry Has Tags',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensures that Azure Machine Learning registries have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Machine Learning registry and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['machineLearning:listRegistries'],
    realtime_triggers: ['microsoftmachinelearningservices:registries:write','microsoftmachinelearningservices:registries:delete', 'microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.machineLearning, function(location, rcb) {
            var machineLearningRegistries = helpers.addSource(cache, source,
                ['machineLearning', 'listRegistries', location]);

            if (!machineLearningRegistries) return rcb();

            if (machineLearningRegistries.err || !machineLearningRegistries.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Machine Learning registries: ' + helpers.addError(machineLearningRegistries), location);
                return rcb();
            }

            if (!machineLearningRegistries.data.length) {
                helpers.addResult(results, 0, 'No existing Machine Learning registries found', location);
                return rcb();
            }

            for (let registry of machineLearningRegistries.data) {
                if (!registry.id) continue; 

                if (registry.tags && Object.entries(registry.tags).length > 0) {
                    helpers.addResult(results, 0,
                        'Machine Learning registry has tags associated', location, registry.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning registry does not have tags associated', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};