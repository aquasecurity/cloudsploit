var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace Diagnostic Logs',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Databricks workspace has diagnostic logs enabled.',
    more_info: 'Enabling diagnostics logs for Azure Databricks workspace helps to monitor detailed usage patterns in your account, access and query your account\'s audit logs, and identifying potential security threats, providing essential insights for effective management and security of your environment.',
    recommended_action: 'Ensure that Azure Databricks workspace has diagnostic logs enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/audit-logs',
    apis: ['databricks:listWorkspaces','diagnosticSettings:listByDatabricksWorkspace'],
    realtime_triggers: ['microsoftdatabricks:workspaces:write','microsoftdatabricks:workspaces:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        const requiredCategories = ['accounts', 'clusters', 'notebook', 'jobs', 'filesystem'];

        async.each(locations.databricks, function(location, rcb) {
            const databricks = helpers.addSource(cache, source,
                ['databricks', 'listWorkspaces', location]);

            if (!databricks) return rcb();

            if (databricks.err || !databricks.data) {
                helpers.addResult(results, 3, 'Unable to query for Databricks Workspaces: ' + helpers.addError(databricks), location);
                return rcb();
            }

            if (!databricks.data.length) {
                helpers.addResult(results, 0, 'No existing Databricks Workspaces found', location);
                return rcb();
            }

            for (let workspace of databricks.data) {
                if (!workspace.id) continue;

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByDatabricksWorkspace', location, workspace.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Databricks workspace diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, workspace.id);
                    continue;
                }

                const hasDestination = diagnosticSettings.data.some(ds =>
                    ds.workspaceId || ds.storageAccountId || ds.eventHubAuthorizationRuleId
                );

                if (!hasDestination) {
                    helpers.addResult(results, 2,
                        'Databricks workspace does not have diagnostic logs configured with a valid destination',
                        location, workspace.id);
                    continue;
                }

                let missingLogs = requiredCategories.slice();
                diagnosticSettings.data.forEach(ds => {
                    if (!ds.logs || !ds.logs.length) return;
                    missingLogs = missingLogs.filter(requiredCategory =>
                        !ds.logs.some(log =>
                            (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) ||
                            (log.categoryGroup === 'allLogs' && log.enabled)
                        )
                    );
                });

                if (missingLogs.length) {
                    helpers.addResult(results, 2,
                        `Databricks workspace does not have diagnostic logs enabled for following: ${missingLogs.join(', ')}`,
                        location, workspace.id);
                } else {
                    helpers.addResult(results, 0, 'Databricks workspace has diagnostic logs enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};