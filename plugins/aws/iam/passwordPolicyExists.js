var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Password Policy Exists',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that password policy is set for IAM users.',
    more_info: 'You can set a custom password policy on your AWS account to specify login password complexity requirements and mandatory rotation periods for your IAM users\' passwords.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html',
    recommended_action: 'Create a password policy under account settings in IAM',
    apis: ['IAM:getAccountPasswordPolicy'],
    realtime_triggers: ['iam:UpdateAccountPasswordPolicy','iam:DeleteAccountPasswordPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);
        var getAccountPasswordPolicy = helpers.addSource(cache, source,
            ['iam', 'getAccountPasswordPolicy', region]);
    
        if (!getAccountPasswordPolicy) return callback(null, results, source);

        // Handle special case errors
        if (getAccountPasswordPolicy.err &&
            getAccountPasswordPolicy.err.code &&
            getAccountPasswordPolicy.err.code === 'NoSuchEntity') {
            helpers.addResult(results, 2, 'Account does not have a password policy');
            return callback(null, results, source);
        }

        if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
            helpers.addResult(results, 3,
                'Unable to query for password policy status: ' + helpers.addError(getAccountPasswordPolicy));
            return callback(null, results, source);
        }

        helpers.addResult(results, 0, 'Account has a password policy');
        callback(null, results, source);
    },    
};