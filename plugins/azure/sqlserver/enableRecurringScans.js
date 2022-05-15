var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Recurring Scans',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensures that Period Recurring Scans is enabled for SQL Servers',
    more_info: 'VA setting Periodic recurring scans schedules periodic (weekly) vulnerability scanning for the SQL server and corresponding Databases. Periodic and regular vulnerability scanning provides risk visibility based on updated known vulnerability signatures and best practices.',
    recommended_action: 'Ensure that recurringScans is set to Enabled',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-vulnerability-assessment',
    apis: ['servers:listSql', 'vulnerabilityAssessments:listByServer'],

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
                        'Unable to query for Vulnerability Assessments settings: ' + helpers.addError(vulnerabilityAssessments), location, server.id);
                } else {
                    if (!vulnerabilityAssessments.data.length) {
                        helpers.addResult(results, 2, 'No Vulnerability Assessments settings found', location, server.id);
                    } else {
                        vulnerabilityAssessments.data.forEach(vulnerabilityAssessment => {
                            if (vulnerabilityAssessment.recurringScans && vulnerabilityAssessment.recurringScans.isEnabled) {
                                helpers.addResult(results, 0,
                                    'Recurring Scans for the SQL server is enabled', location, server.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'Recurring Scans for the SQL server is disabled', location, server.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
