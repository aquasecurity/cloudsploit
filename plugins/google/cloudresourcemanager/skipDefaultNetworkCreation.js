
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Skip Default Network Creation',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Skip Default Network Creation" constraint policy is enforces at the GCP organization level.',
    more_info: 'Enforcing the "Skip Default Network Creation" disables the creation of default VPC network on project creation which is recommended if you want to keep some parts of your network private.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Skip Default Network Creation" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],
    remediation_min_version: '202207280432',
    remediation_description: 'The "Skip Default Network Creation" constraint will be enforced at the organization level.',
    apis_remediate: ['organizations:list', 'organizations:listOrgPolicies'],
    actions: {remediate:['SetOrgPolicy'], rollback:['SetOrgPolicy']},
    permissions: {remediate: ['orgpolicy.policy.set'], rollback: ['orgpolicy.policy.set']},
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

        helpers.checkOrgPolicy(orgPolicies, 'compute.skipDefaultNetworkCreation', 'booleanPolicy', true, false, 'Skip Default Network Creation', results, organization);

        return callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'skipDefaultNetworkCreation';
 
        var putCall = this.actions.remediate;

        helpers.remediateOrgPolicy(config, 'constraints/compute.skipDefaultNetworkCreation', 'booleanPolicy', true, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled'
            };

            callback(null, action);
        });
    }
};