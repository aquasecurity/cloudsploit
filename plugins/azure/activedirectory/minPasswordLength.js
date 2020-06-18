const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Minimum Password Length',
    category: 'Active Directory',
    description: 'Ensures that all Azure passwords require a minimum length',
    more_info: 'Azure handles most password policy settings, including the minimum password length, defaulted to 8 characters.',
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
            helpers.addResult(results, 0, 'Minimum password length is 8 characters', 'global');
            callback(null, results, source);
        });
    }
};
