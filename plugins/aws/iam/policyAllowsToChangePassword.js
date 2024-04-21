var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Password Policy Allows To Change Password',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure IAM password policy allows users to change their passwords.',
    more_info: 'Password policy should allow users to rotate their passwords as a security best practice.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Update the password policy for users to change their passwords',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for password to be changed by users will be set to true.',
    remediation_min_version: '202209040720',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    remediation_inputs: {
        allowUsersToChangePasswordsCreatePolicy: {
            name: 'Create Password Policy',
            description: 'Whether to create a new password policy if one does not already exist.',
            regex: '^(true|false)$',
            required: false
        }
    },
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires a strong password policy. Setting IAM password ' +
             'requirements enforces this policy.',
        cis1: '1.6 Ensure IAM password policy allows users to change their passwords'
    },
    realtime_triggers: ['iam:UpdateAccountPasswordPolicy','iam:DeleteAccountPasswordPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var getAccountPasswordPolicy = helpers.addSource(cache, source,
            ['iam', 'getAccountPasswordPolicy', region]);

        if (!getAccountPasswordPolicy) return callback(null, results, source);

        // Handle default password policy
        if (getAccountPasswordPolicy.err &&
            getAccountPasswordPolicy.err.code &&
            getAccountPasswordPolicy.err.code === 'NoSuchEntity') {
            helpers.addResult(results, 2, 'Account has Default password policy');
            return callback(null, results, source);
        }

        if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
            helpers.addResult(results, 3,
                'Unable to query for password policy status: ' + helpers.addError(getAccountPasswordPolicy));
            return callback(null, results, source);
        }

        var passwordPolicy = getAccountPasswordPolicy.data;

        if (!passwordPolicy.AllowUsersToChangePassword) {
            helpers.addResult(results, 2, 'Password policy does not allow users to change their password');
        } else {
            helpers.addResult(results, 0, 'Password policy allow users to change their password');
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'policyAllowsToChangePassword';
        var passwordKey = 'AllowUsersToChangePassword';

        var input = {};
        input[passwordKey] = true;

        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};