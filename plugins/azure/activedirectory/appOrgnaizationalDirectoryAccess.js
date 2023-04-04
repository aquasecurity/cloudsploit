const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure App Organizational Directory Access',
    category: 'Active Directory',
    domain: 'Identity and Access Management',
    description: 'Ensures that Azure Apps are accessible to accounts in organizational directory only.',
    more_info: 'AAD provides different types of account access. By using single-tenant authentication, the impact is limited to the application’s tenant – all users from the same tenant could connect to the application and save app from unauthorized access.',
    link: 'https://learn.microsoft.com/en-us/azure/active-directory/develop/single-and-multi-tenant-apps',
    recommended_action: 'Modify the Azure app authentication setting and provide access to accounts in  organizational directory only',
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
                helpers.addResult(results, 3, 'Unable to query for applications: ' + helpers.addError(applications), location);
                return rcb();
            }
            if (!applications.data.length) {
                helpers.addResult(results, 0, 'No existing application found', location);
                return rcb();
            }
            console.log(applications)
            for (let app of applications.data) {
                if (!app.id) continue;

                if (app.signInAudience && app.signInAudience === 'AzureADMultipleOrgs' || app.signInAudience === 'AzureADandPersonalMicrosoftAccount'){
                    helpers.addResult(results, 2, 'Multi tenant access enabled for the application.', location, app.displayName);
                } else {
                    helpers.addResult(results, 0, 'Single tenant access enabled for the application.', location, app.displayName);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
