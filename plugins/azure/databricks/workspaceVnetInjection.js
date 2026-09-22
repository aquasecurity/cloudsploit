var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace VNet Injection',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Databricks Workspace is deployed in a customer-managed virtual network.',
    more_info: 'By default, Azure Databricks creates a managed virtual network which provides limited control over network security policies, firewall configurations and routing. Deploying the workspace in a customer-managed virtual network (VNet injection) keeps compute clusters within the organization network boundary and allows restricted outbound access, fine-grained NSG policies and private connectivity.',
    recommended_action: 'Recreate the Databricks workspace with a customer-managed virtual network.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/vnet-inject',
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

                if (workspace.parameters && workspace.parameters.customVirtualNetworkId && workspace.parameters.customVirtualNetworkId.value) {
                    helpers.addResult(results, 0, 'Databricks workspace is deployed in a customer-managed virtual network', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Databricks workspace is not deployed in a customer-managed virtual network', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
