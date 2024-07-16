var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace Diagnostic Logging Enabled',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures diagnostic logging is enabled for Synapse workspace.',
    more_info: 'Enabling diagnostic logging for Azure Synapse workspace enhances performance monitoring, troubleshooting, and security optimization. This feature captures detailed logs of workspace activities, allowing you to gain insights, identify issues, and maintain the integrity and efficiency of data operations.',
    recommended_action: 'Enable diagnostic logging for all Synapse workspaces.',
    link: 'https://learn.microsoft.com/en-gb/azure/azure-monitor/essentials/diagnostic-settings',
    apis: ['synapse:listWorkspaces', 'diagnosticSettings:listByWorkspaces'],
    realtime_triggers: ['microsoftsynapse:workspaces:write','microsoftsynapse:workspaces:delete','microsoftinsights:diagnosticSettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.synapse, function(location, rcb) {
            const workspaces = helpers.addSource(cache, source,
                ['synapse', 'listWorkspaces', location]);

            if (!workspaces) return rcb();


            if (workspaces.err || !workspaces.data) {
                helpers.addResult(results, 3, 'Unable to query Synapse workspaces: ' + helpers.addError(workspaces), location);
                return rcb();
            }

            if (!workspaces.data.length) {
                helpers.addResult(results, 0, 'No existing Synapse workspaces found', location);
                return rcb();
            }

            for (let workspace of workspaces.data) {
                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByWorkspaces', location, workspace.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Synapse workspace diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, workspace.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'Synapse workspace has diagnostic logs enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Synapse workspace does not have diagnostic logs enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};