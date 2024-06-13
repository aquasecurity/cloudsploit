var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace AAD Auth Enabled',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that Azure Synapse Analytics Workspace have AAD Auth enabled.',
    more_info: 'Enabling Microsoft Entra ID (AAD) Authentication for your Synapse workspace enhances security by ensuring that only authenticated and authorized users can access your resources. This feature integrates seamlessly with AAD, providing robust access control and simplifying user management.',
    recommended_action: 'Modify Synapse Workspace and enable microsoft entra id authentication.',
    link: 'https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/active-directory-authentication',
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
                if (workspace.azureADOnlyAuthentication) {
                    helpers.addResult(results, 0, 'Synapse workspace has AAD auth enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Synapse workspace does not have AAD auth enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};