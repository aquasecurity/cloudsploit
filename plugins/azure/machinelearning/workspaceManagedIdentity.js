var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace Managed Identity',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that Machine Learning Workspaces have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify Machine Learning Workspaces and add managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/how-to-identity-based-service-authentication',
    apis: ['machineLearning:listWorkspaces', 'diagnosticSettings:listByMachineLearningWorkspce'],
    realtime_triggers: ['microsoft:machinelearningservices:workspaces:write', 'microsoft:machinelearningservices:workspaces:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

                if (workspace.identity && workspace.identity.type && 
                    (workspace.identity.type.toLowerCase() === 'systemassigned' || workspace.identity.type.toLowerCase() === 'userassigned')) {
                    helpers.addResult(results, 0,
                        'Machine Learning workspace has managed identity enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning workspace does not have managed identity enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};