var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Restrict Load Balancer Creation',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Restrict Load Balancer Creation for Types" is enforced on the GCP organization level.',
    more_info: 'Enforcing the "Restrict Load Balancer Creation for Types" constraint allows you to control which type of load balancers can be created within your organization.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict Load Balancer Creation for Types" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],

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

        helpers.checkOrgPolicy(orgPolicies, 'compute.restrictLoadBalancerCreationForTypes', 'listPolicy', true, false, 'Restrict Load Balancer Creation for Types', results, organization);

        return callback(null, results, source);
    }
};