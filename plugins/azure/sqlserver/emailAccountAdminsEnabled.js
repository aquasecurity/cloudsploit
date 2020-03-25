var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Email Account Admins Enabled',
    category: 'SQL Server',
    description: 'Ensures that email account admins is enabled in advanced data security for SQL servers.',
    more_info: 'Enabling email account admins in advanced data security on all SQL servers ensures that monitored data for unusual activity, vulnerabilities, and threats get sent to the account admins and subscription owners.',
    recommended_action: 'Ensure that also send email notification to admins and subscription owners is enabled in advanced threat protections for all SQL servers.',
    link: 'https://docs.microsoft.com/en-gb/azure/sql-database/sql-database-advanced-data-security',
    apis: ['resourceGroups:list', 'servers:listByResourceGroup', 'serverSecurityAlertPolicies:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.serverSecurityAlertPolicies, function (location, rcb) {

            const serverSecurityAlertPolicies = helpers.addSource(cache, source,
                ['serverSecurityAlertPolicies', 'listByServer', location]);

            if (!serverSecurityAlertPolicies) return rcb();

            if (serverSecurityAlertPolicies.err || !serverSecurityAlertPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Database Threat Detection Policies: ' + helpers.addError(serverSecurityAlertPolicies), location);
                return rcb();
            }

            if (!serverSecurityAlertPolicies.data.length) {
                helpers.addResult(results, 0, 'No Database Threat Detection policies found', location);
                return rcb();
            }

            serverSecurityAlertPolicies.data.forEach(serverSecurityAlertPolicy => {
                var serverIdArr = serverSecurityAlertPolicy.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');

                if (serverSecurityAlertPolicy.state &&
                    serverSecurityAlertPolicy.state == 'Enabled' &&
                    serverSecurityAlertPolicy.emailAccountAdmins) {
                    helpers.addResult(results, 0,
                        'Email Account Admins is enabled on the sql server', location, serverId);
                } else {
                    helpers.addResult(results, 2,
                        'Email Account Admins is not enabled on the sql server', location, serverId);
                }
            });
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};