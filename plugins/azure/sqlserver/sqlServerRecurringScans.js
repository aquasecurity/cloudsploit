var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Recurring Scans Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that Period Recurring Scans feature is enabled for SQL Servers.',
    more_info: 'Setting periodic recurring scans schedules periodic (weekly) vulnerability scanning for the SQL server and corresponding Databases. Periodic and regular vulnerability scanning provides risk visibility based on updated known vulnerability signatures and best practices.',
    recommended_action: 'Ensure that recurring scans feature is set to Enabled.',
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
                        let recScansEnabled = vulnerabilityAssessments.data.find(vulnerabilityAssessment =>
                            vulnerabilityAssessment.recurringScans && vulnerabilityAssessment.recurringScans.isEnabled);

                        if (recScansEnabled) {
                            helpers.addResult(results, 0,
                                'Recurring Scans for the SQL server is enabled', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Recurring Scans for the SQL server is disabled', location, server.id);
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