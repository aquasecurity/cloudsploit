var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace Public Access',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Databricks Workspace has public network access disabled.',
    more_info: 'Disabling public network access ensures that the Databricks workspace is not reachable over the public internet and can only be accessed through private endpoints within trusted networks. This reduces the attack surface and the risk of unauthorized access.',
    recommended_action: 'Modify Databricks workspace networking settings and set Allow Public Network Access to disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/security/network/front-end/front-end-private-connect',
    apis: ['databricks:listWorkspaces'],
    realtime_triggers: ['microsoftdatabricks:workspaces:write','microsoftdatabricks:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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

                if (workspace.publicNetworkAccess && workspace.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0, 'Databricks workspace has public network access disabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Databricks workspace has public network access enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
