var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace Has Tags',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensures that Machine Learning Workspaces have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Machine Learning Workspace and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['machineLearning:listWorkspaces'],
    realtime_triggers: ['microsoft:machinelearningservices:workspaces:write', 'microsoft:machinelearningservices:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.containerApps, function(location, rcb) {

            var machineLearningWorkspaces = helpers.addSource(cache, source,
                ['machineLearning', 'listWorkspaces', location]);

            if (!machineLearningWorkspaces) return rcb();

            if (machineLearningWorkspaces.err || !machineLearningWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Machine Learning workspaces: ' + helpers.addError(machineLearningWorkspaces), location);
                return rcb();
            }

            if (!machineLearningWorkspaces.data.length) {
                helpers.addResult(results, 0, 'No existing Machine Learning workspace found', location);
                return rcb();
            }

            for (let workspace of machineLearningWorkspaces.data) {
                if (!workspace.id) continue; 

                if (workspace.tags && Object.entries(workspace.tags).length > 0) {
                    helpers.addResult(results, 0,
                        'Machine Learning workspace has tags associated', location, workspace.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning workspace does not have tags associated', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};