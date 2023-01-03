var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Essential Contacts Configured',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Ensure Essential Contacts is configured to designate email addresses for Google Cloud services to notify of important technical or security information.',
    more_info: 'Many Google Cloud services, such as Cloud Billing, send out notifications to share important information with Google Cloud users. By default, these notifications are sent to members with certain Identity and Access Management (IAM) roles. With Essential Contacts, you can customize who receives notifications by providing your own list of contacts.',
    link: 'https://cloud.google.com/resource-manager/docs/managing-notification-contacts',
    recommended_action: 'Ensure Essential Contacts is configured for organization.',
    apis: ['organizations:list', 'organizations:essentialContacts'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let organizations = helpers.addSource(cache, source,
            ['organizations','list', 'global']);

        if (!organizations || organizations.err || !organizations.data || !organizations.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for organizations: ' + helpers.addError(organizations), 'global', null, null, (organizations) ? organizations.err : null);
            return callback(null, results, source);
        }

        var organization = organizations.data[0].name;

        let essentialContacts = helpers.addSource(cache, source,
            ['organizations', 'essentialContacts', 'global']);

        if (!essentialContacts) return callback(null, results, source);

        if (essentialContacts.err || !essentialContacts.data) {
            helpers.addResult(results, 3, 'Unable to query essential contacts for organization', 'global', null, null, essentialContacts.err);
            return callback(null, results, source);
        }

        if (essentialContacts.data && essentialContacts.data.length && essentialContacts.data[0]
            && essentialContacts.data[0].contacts && essentialContacts.data[0].contacts.length) {
            helpers.addResult(results, 0, 'Essential Contacts is configured for organization', 'global', organization);
        } else {
            helpers.addResult(results, 2, 'Essential Contacts is not configured for organization', 'global', organization);
        }

        return callback(null, results, source);
    }
};