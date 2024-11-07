const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Approved Certificates Only',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Azure Automation accounts are only using approved certificates.',
    more_info: 'Certificates in azure automation accounts should be approved by the organization to meet the organizational security requirements. ',
    recommended_action: 'Ensure that Azure Automation accounts are only using approved certificates.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/shared-resources/certificates',
    apis: ['automationAccounts:list', 'certificates:listByAutomationAccounts'],
    settings: {
        ca_approved_certificates: {
            name: 'Approved CA Certificates',
            description: 'List of comma separated approved certificates names',
            regex: '^.*$',
            default: ''
        }
    },
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:delete'],
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var config = {
            approvedCertificates: settings.ca_approved_certificates || this.settings.ca_approved_certificates.default
        };

        if (!config.approvedCertificates.length) return callback(null, results, source);

        var certificatesList = config.approvedCertificates.toLowerCase().split(',');

        async.each(locations.automationAccounts, (location, rcb) => {
            const automationAccounts = helpers.addSource(cache, source,
                ['automationAccounts', 'list', location]);

            if (!automationAccounts) return rcb();

            if (automationAccounts.err || !automationAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query Automation accounts: ' + helpers.addError(automationAccounts), location);
                return rcb();
            }

            if (!automationAccounts.data.length) {
                helpers.addResult(results, 0, 'No existing Automation accounts found', location);
                return rcb();
            }

            for (var account of automationAccounts.data) {
                const acctCertificates = helpers.addSource(cache, source,
                    ['certificates', 'listByAutomationAccounts', location, account.id]);

                if (acctCertificates.err || !acctCertificates.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Automation accounts certificates: ' + helpers.addError(acctCertificates), location, account.id);
                    continue;
                }

                if (!acctCertificates.data.length) {
                    helpers.addResult(results, 0, 'No existing certificates found for Automation Account', location, account.id);
                } else {
                    var unapprovedCerts = acctCertificates.data.filter(cert => 
                        cert.name && !certificatesList.includes(cert.name.toLowerCase())).map(function(cert) {
                        return cert.name;
                    });
                    if (unapprovedCerts && unapprovedCerts.length) {
                        helpers.addResult(results, 2, `Automation account is using following unapproved certificates: ${unapprovedCerts.join(',')}`, location, account.id);
                    } else {
                        helpers.addResult(results, 0, 'Automation account is using approved certificates only', location, account.id);
                    }
                }


            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

