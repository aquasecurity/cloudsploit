var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Enforce Restrict Authorized Networks',
    category: 'Resource Manager',
    domain: 'Management and Governance',
    description: 'Determine if "Restrict Authorized Networks on Cloud SQL instances" policy is enforced at the GCP organization level.',
    more_info: 'Enforcing "Restrict Authorized Networks on Cloud SQL instances" organization policy, restricts adding authorized networks for unproxied database access to Cloud SQL instances.',
    link: 'https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints',
    recommended_action: 'Ensure that "Restrict Authorized Networks on Cloud SQL instances" constraint is enforced at the organization level.',
    apis: ['organizations:list', 'organizations:listOrgPolicies'],
    remediation_min_version: '202207280432',
    remediation_description: 'The "Restrict Authorized Networks on Cloud SQL instances" constraint will be enforced at the organization level.',
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

        helpers.checkOrgPolicy(orgPolicies, 'sql.restrictAuthorizedNetworks', 'booleanPolicy', true, false, 'Restrict Authorized Networks on Cloud SQL instances', results, organization);

        return callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;

        // inputs specific to the plugin
        var pluginName = 'restrictAuthorizedNetworks';
 
        var putCall = this.actions.remediate;

        helpers.remediateOrgPolicy(config, 'constraints/sql.restrictAuthorizedNetworks', 'booleanPolicy', true, resource, remediation_file, putCall, pluginName, function(err, action) {
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