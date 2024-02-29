const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Valid Source Controls',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensure that Azure Automation account are not using undesired source controls.',
    more_info: 'Automation accounts should only use allowed source controls in order to follow your organizations\'s security and compliance requirements.',
    recommended_action: 'Ensure disallowed valid source controls are not being used for Automation accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/source-control-integration',
    apis: ['automationAccounts:list', 'sourceControls:listByAutomationAccounts'],
    settings: {
        automation_account_disallowed_source_controls: {
            name: 'Automation Account Disallowed Source Controls',
            description: 'A comma-separated list of source controls which should not be used',
            regex: '^((vsoGit|vsoTfvc|gitHub),? ?){1,3}$',
            default: ''
        }
    },
    realtime_triggers: ['microsoftautomation:automationaccounts:runbooks:write', 'microsoftautomation:automationaccounts:runbooks:delete', 'microsoftautomation:automationaccounts:sourcecontrols:write', 'microsoftautomation:automationaccounts:sourcecontrols:delete'],

    run: function(cache, settings, callback) {

        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var config = {
            automation_account_disallowed_source_controls: settings.automation_account_disallowed_source_controls || this.settings.automation_account_disallowed_source_controls.default
        };

        if (!config.automation_account_disallowed_source_controls.length) return callback(null, results, source);

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
                if (!account.id) continue;

                var sourceControls = helpers.addSource(cache, source,
                    ['sourceControls', 'listByAutomationAccounts', location, account.id]);

                if (!sourceControls || sourceControls.err || !sourceControls.data) {
                    helpers.addResult(results, 3, `Unable to query Automation account source controls: ${helpers.addError(sourceControls)}`,
                        location, account.id);
                    continue;
                } else if (!sourceControls.data.length) {
                    helpers.addResult(results, 0, 'No existing Automation accounts source controls found', location);
                    continue;
                } else {
                    var disallowedSourceControls = config.automation_account_disallowed_source_controls.toLowerCase().split(',');

                    var foundDisallowedControls = [];
                    sourceControls.data.forEach(sourceControl => {
                        if (sourceControl.sourceType && disallowedSourceControls.includes(sourceControl.sourceType.toLowerCase()) &&
                            !foundDisallowedControls.includes(sourceControl.sourceType)) {
                            foundDisallowedControls.push(sourceControl.sourceType);
                        }
                    });

                    if (foundDisallowedControls && foundDisallowedControls.length) {
                        helpers.addResult(results, 2, `Automation account is using the following source controls: ${foundDisallowedControls.join(',')} which should not be used`, location, account.id);

                    } else {
                        helpers.addResult(results, 0, 'Automation account is using valid source controls', location, account.id);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

