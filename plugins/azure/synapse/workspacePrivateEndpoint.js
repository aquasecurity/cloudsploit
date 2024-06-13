var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace Private Endpoints',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that Azure Synapse Analytics Workspace are accessible only through private endpoints.',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. Private Endpoint uses a private IP address from your VNet, effectively bringing the service such as Azure Storage Accounts into your VNet.',
    recommended_action: 'Modify Synapse Workspace and configure private endpoints.',
    link: 'https://learn.microsoft.com/en-us/azure/synapse-analytics/security/how-to-connect-to-workspace-with-private-links',
    apis: ['synapse:listWorkspaces'],
    realtime_triggers: [],

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
                if (workspace.privateEndpointConnections &&
                    workspace.privateEndpointConnections.length) {
                    helpers.addResult(results, 0, 'Private endpoints are configured for the Synapse workspace', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Private endpoints are not configured for the Synapse workspace', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};