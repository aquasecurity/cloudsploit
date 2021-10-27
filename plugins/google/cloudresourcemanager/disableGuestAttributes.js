var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Disable Guest Attributes',
    category: 'Resource Manager',
    description: 'Determine if "Disable Guest Attributes of Compute Engine Metadata" constraint policy is enabled at the GCP organization level.',
    more_info: 'Guest attributes are used for VM instance configuration. For security reasons, ensure that users cannot configure guest attributes for your VM instances.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Disable Guest Attributes of Compute Engine Metadata" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let listOrgPolicies = helpers.addSource(cache, source,
            ['organizations', 'listOrgPolicies', 'global']);

        if (!listOrgPolicies) return callback(null, results, source);

        if (listOrgPolicies.err || !listOrgPolicies.data) {
            helpers.addResult(results, 3, 'Unable to query organization policies', 'global', null, null, listOrgPolicies.err);
            return callback(null, results, source);
        }

        if (!listOrgPolicies.data.length) {
            helpers.addResult(results, 0, 'No organization policies found', 'global');
            return callback(null, results, source);
        }
        let orgPolicies = listOrgPolicies.data[0];

        helpers.checkOrgPolicy(orgPolicies, 'compute.disableGuestAttributesAccess', 'booleanPolicy', true, false, 'Disable Guest Attributes of Compute Engine Metadata', results);

        return callback(null, results, source);
    }
};