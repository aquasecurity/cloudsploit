const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Analytics Public Workspace',
    category: 'Monitor',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensures Log Analytics Workspace is not publicly accessible.',
    more_info: 'Securing Log Analytics workspaces through private links, and disallowing public access, enhances data protection, access control, and overall security by restricting entry to authorized networks and minimizing potential external threats.',
    recommended_action: 'Configure Log Analytics workspaces with private links and deny access from public networks.' ,
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/private-link-configure#configure-access-to-your-resources',
    apis: ['logAnalytics:listWorkspaces'],
    realtime_triggers: ['microsoftoperationalinsights:workspaces:write', 'microsoftoperationalinsights:workspaces::delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.logAnalytics, (location, rcb) => {
            const logAnalytics = helpers.addSource(cache, source,
                ['logAnalytics', 'listWorkspaces', location]);

            if (!logAnalytics) return rcb();

            if (logAnalytics.err || !logAnalytics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Log Analytics Workspaces: ' + helpers.addError(logAnalytics), location);
                return rcb();
            }

            if (!logAnalytics.data.length) {
                helpers.addResult(results, 2, 'No existing Log Analytics Workspaces found', location);
                return rcb();
            }

            logAnalytics.data.forEach(function(workspace){

                if ((workspace.publicNetworkAccessForIngestion && workspace.publicNetworkAccessForIngestion.toLowerCase() === 'enabled') || (workspace.publicNetworkAccessForQuery && workspace.publicNetworkAccessForQuery.toLowerCase() === 'enabled')) {
                    helpers.addResult(results, 2,
                        'Log Analytics Workspace is publicly accessible', location, workspace.id);
                } else {
                    helpers.addResult(results, 0,
                        'Log Analytics Workspace is not publicly accessible', location, workspace.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
