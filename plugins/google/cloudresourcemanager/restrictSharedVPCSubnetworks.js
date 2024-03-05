var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Restrict Shared VPC Subnetworks',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Determine if "Restrict Shared VPC Subnetworks" is enforced on the GCP organization level.',
    more_info: 'Enforcing the "Restrict Shared VPC Subnetworks" constraint allows you to define which VPC Shared Subnetworks your resources can use within your GCP organization.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict Shared VPC Subnetworks" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],
    realtime_triggers: ['SetOrgPolicy'],

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

        helpers.checkOrgPolicy(orgPolicies, 'compute.restrictSharedVpcSubnetworks', 'listPolicy', true, false, 'Restrict Shared VPC Subnetworks', results, organization);

        return callback(null, results, source);
    }
};