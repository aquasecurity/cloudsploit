var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Restrict VPN Peer IPs',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Restrict VPN Peer IPs" is enforced on the GCP organization level.',
    more_info: 'Enforcing the "Restrict VPN Peer IPs" constraint allows you to control the IP addresses which can be configured as VPN Peers.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict VPN Peer IPs" constraint is enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.restrictVpnPeerIPs', 'listPolicy', true, false, 'Restrict VPN Peer IPs', results);

        return callback(null, results, source);
    }
};