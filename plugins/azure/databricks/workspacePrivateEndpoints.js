var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace Private Endpoints',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Databricks Workspace has an approved private endpoint connection.',
    more_info: 'Private endpoints allow clients and services to access the Databricks workspace over an encrypted Private Link using a private IP address from the virtual network. This keeps traffic off the public internet and reduces the attack surface. A private endpoint connection only carries traffic once its connection state is approved.',
    recommended_action: 'Create a private endpoint for the Databricks workspace and approve the private endpoint connection.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/private-link',
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

                var approved = workspace.privateEndpointConnections && workspace.privateEndpointConnections.length ?
                    workspace.privateEndpointConnections.some(connection => connection.properties &&
                        connection.properties.privateLinkServiceConnectionState &&
                        connection.properties.privateLinkServiceConnectionState.status &&
                        connection.properties.privateLinkServiceConnectionState.status.toLowerCase() === 'approved') : false;

                if (approved) {
                    helpers.addResult(results, 0, 'Databricks workspace has an approved private endpoint connection', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Databricks workspace does not have an approved private endpoint connection', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
