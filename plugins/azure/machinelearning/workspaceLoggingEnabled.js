var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace Diagnostic Logs',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that diagnostic logging is enabled for Machine Learning workspaces.',
    more_info: 'Enabling diagnostic logs for Machine Learning workspaces is crucial to collect resource logs, which provide detailed data about resource operations. It helps to gain valuable insights into resource activity, assisting in monitoring, diagnosing issues, and optimizing the performance of Azure resources.',
    recommended_action: 'Enable diagnostic logging for all Machine Learning workspaces.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/monitor-azure-machine-learning',
    apis: ['machineLearning:listWorkspaces', 'diagnosticSettings:listByMachineLearningWorkspce'],
    realtime_triggers: ['microsoft:machinelearningservices:workspaces:write', 'microsoft:machinelearningservices:workspaces:delete', 'microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

                var diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByMachineLearningWorkspce', location, workspace.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query Machine Learning workspace diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, workspace.id);
                    continue;
                }
                
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
                if (found) {
                    helpers.addResult(results, 0, 'Machine Learning workspace has diagnostic logs enabled', location, workspace.id);

                } else {
                    helpers.addResult(results, 2, 'Machine Learning workspace does not have diagnostic logs enabled' , location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};