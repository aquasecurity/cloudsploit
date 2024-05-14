var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace Public Access Disabled',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensures that Azure Machine Learning workspaces are not publicly accessible.',
    more_info: 'Disabling public network access enhances security by preventing Machine Learning workspaces from being accessible on the public internet. You can manage workspace exposure by establishing private endpoints instead.',
    recommended_action: 'Ensure that Azure Machine Learning workspaces have public network access disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/how-to-secure-workspace-vnet',
    apis: ['machineLearning:listWorkspaces'],
    realtime_triggers: ['microsoftcognitiveservices:accounts:write','microsoftcognitiveservices:accounts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.machineLearning, function(location, rcb) {

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

                if (workspace.publicNetworkAccess && workspace.publicNetworkAccess.toLowerCase()=='disabled') {
                    helpers.addResult(results, 0,
                        'Machine Learning workspace is not publicly accessible', location, workspace.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning workspace is publicly accessible', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};