var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Server Send Email to Admin and Owners',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that Send Emails to admins and owners is enabled for SQL Servers.',
    more_info: 'Vulnerability Assessment (VA) scan reports and alerts will be sent to email addresses configured at "Send scan reports to". This may help in reducing time required for identifying risks and taking corrective measures.',
    recommended_action: 'Configure Send scan reports to email addresses of concerned data owners/stakeholders for critical SQL servers.',
    link: 'https://learn.microsoft.com/en-us/azure/sql-database/sql-vulnerability-assessment',
    apis: ['servers:listSql', 'vulnerabilityAssessments:listByServer'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete','microsoftsql:servers:sqlvulnerabilityassessments:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const vulnerabilityAssessments = helpers.addSource(cache, source,
                    ['vulnerabilityAssessments', 'listByServer', location, server.id]);

                if (!vulnerabilityAssessments || vulnerabilityAssessments.err || !vulnerabilityAssessments.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Vulnerability Assessments setting: ' + helpers.addError(vulnerabilityAssessments), location, server.id);
                } else {
                    if (!vulnerabilityAssessments.data.length) {
                        helpers.addResult(results, 2, 'No Vulnerability Assessments setting found', location, server.id);
                    } else {
                        let emailNotificationEnabled = vulnerabilityAssessments.data.find(vulnerabilityAssessment =>
                            vulnerabilityAssessment.recurringScans && vulnerabilityAssessment.recurringScans.emailSubscriptionAdmins);
                        if (emailNotificationEnabled) {
                            helpers.addResult(results, 0,
                                'Send Email notifications to admins for the SQL server is enabled', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Send Email notifications to admins for the SQL server is disabled', location, server.id);
                        }
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};