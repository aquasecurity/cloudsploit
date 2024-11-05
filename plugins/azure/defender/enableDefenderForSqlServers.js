var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For SQL Servers',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensures that Microsoft Defender is enabled for Azure SQL Server Databases at subscription level or individual resource level.',
    more_info: 'Turning on Microsoft Defender for Azure SQL Server Databases enables threat detection for Azure SQL database servers, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.',
    recommended_action: 'Turning on Microsoft Defender for Azure SQL Databases incurs an additional cost per resource.',
    link: 'https://learn.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities',
    apis: ['pricings:list', 'servers:listSql', 'serverSecurityAlertPolicies:listByServer'],
    settings: {
        check_level: {
            name: 'Defender Check Level',
            description: 'Check for Defender at subscription level or resource level',
            regex: '^(subscription|resource)$',
            default: 'subscription'
        }
    },
    realtime_triggers: ['microsoftsecurity:pricings:write','microsoftsecurity:pricings:delete','microsoftsql:servers:securityalertpolicies:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            check_level: settings.check_level || this.settings.check_level.default
        }; 

        var serviceName = 'sqlservers';
        var serviceDisplayName = 'SQL Servers';

        
        if (config.check_level === 'subscription') {
            var pricings = helpers.addSource(cache, source, ['pricings', 'list', 'global']);

            if (!pricings) return callback(null, results, source);

            if (pricings.err || !pricings.data) {
                helpers.addResult(results, 3,
                    'Unable to query Pricing information: ' + helpers.addError(pricings), 'global');
                return callback(null, results, source);
            }

            if (!pricings.data.length) {
                helpers.addResult(results, 0, 'No Pricing information found', 'global');
                return callback(null, results, source);
            }


            let pricingData = pricings.data.find((pricing) => pricing.name.toLowerCase() === serviceName);
        
            if (pricingData && pricingData.pricingTier && pricingData.pricingTier.toLowerCase() === 'standard') {
                helpers.addResult(results, 0, 
                    `Azure Defender is enabled for ${serviceDisplayName} at subscription level`, 'global', pricingData.id);
            } else {
                helpers.addResult(results, 2,
                    `Azure Defender is not enabled for ${serviceDisplayName} at subscription level`, 'global');
            }
            return callback(null, results, source);
        }

        async.each(locations.servers, function(location, rcb) {
            const servers = helpers.addSource(cache, source,
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

            servers.data.forEach(server => {
                const securitySettings = helpers.addSource(cache, source,
                    ['serverSecurityAlertPolicies', 'listByServer', location, server.id]);

                if (!securitySettings || securitySettings.err || !securitySettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server security alert policies: ' + helpers.addError(securitySettings),
                        location, server.id);
                } else {
                    securitySettings.data.forEach(setting => {
                        if (setting.state && setting.state.toLowerCase() === 'enabled') {
                            helpers.addResult(results, 0,
                                'Azure Defender is enabled for SQL server', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Azure Defender is not enabled for SQL server', location, server.id);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};