const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Password Requires Lowercase',
    category: 'Active Directory',
    description: 'Ensures that all Azure passwords require lowercase characters',
    more_info: 'Azure handles most password policy settings, including which character types are required. Azure requires 3 out of 4 of the following character types: lowercase, uppercase, special characters, and numbers.',
    link: 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-policy#password-policies-that-only-apply-to-cloud-user-accounts',
    recommended_action: 'No action necessary. Azure handles password requirement settings.',
    apis: ['resources:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.resources, function(location, rcb) {

            const resources = helpers.addSource(cache, source, 
                ['resources', 'list', location]);

            if (!resources) return rcb();

            if (resources.err || !resources.data) {
                helpers.addResult(results, 3, 'Unable to query for resources: ' + helpers.addError(resources), location);
                return rcb();
            }

            rcb();
        }, function() {
            // Global checking goes here
            helpers.addResult(results, 0, 'Password requires lowercase by default', 'global');
            callback(null, results, source);
        });
    }
};