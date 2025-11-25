const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Entra ID App Organizational Directory Access',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that Azure Entra Id applications are accessible to accounts in organisational directory only.',
    more_info: 'Entra ID provides different types of account access. By using single-tenant authentication, the impact gets limited to the application’s tenant i.e. all users from the same tenant could connect to the application and save app from unauthorised access.',
    link: 'https://learn.microsoft.com/en-us/entra/identity-platform/single-and-multi-tenant-apps',
    recommended_action: 'Modify the Azure app authentication setting and provide access to accounts in organisational directory only',
    apis: ['applications:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.applications, function(location, rcb) {
            const applications = helpers.addSource(cache, source,
                ['applications', 'list', location]);

            if (!applications) return rcb();

            if (applications.err || !applications.data) {
                helpers.addResult(results, 3, 'Unable to query for Entra ID applications: ' + helpers.addError(applications), location);
                return rcb();
            }
            if (!applications.data.length) {
                helpers.addResult(results, 0, 'No existing Entra ID applications found', location);
                return rcb();
            }
            for (let app of applications.data) {
                if (!app.appId) continue;

                if (app.signInAudience && app.signInAudience === 'AzureADMultipleOrgs' || app.signInAudience === 'AzureADandPersonalMicrosoftAccount'){
                    helpers.addResult(results, 2, 'Entra ID application has multi-tenant access enabled', location, app.appId);
                } else {
                    helpers.addResult(results, 0, 'Entra ID application has single-tenant access enabled', location, app.appId);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
