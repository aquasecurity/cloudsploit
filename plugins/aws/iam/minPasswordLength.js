var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Minimum Password Length',
    category: 'IAM',
    description: 'Ensures password policy requires a password of at least 14 characters',
    more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Increase the minimum length requirement for the password policy',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for minimum password length will be set to the value set by the user. Otherwise, it will default to 14.',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires that passwords have a minimum length of at least 7 characters. ' +
             'Setting an IAM password length policy enforces this requirement.'
    },
    settings: {
        min_password_length_fail: {
            name: 'Min Password Length Fail',
            description: 'Return a failing result when min password length is fewer than this number of characters',
            regex: '^[1-9]{1}[0-9]{0,2}$',
            default: 10
        },
        min_password_length_warn: {
            name: 'Min Password Length Warn',
            description: 'Return a warning result when min password length is fewer than this number of characters',
            regex: '^[1-9]{1}[0-9]{0,2}$',
            default: 14
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            min_password_length_fail: settings.min_password_length_fail || this.settings.min_password_length_fail.default,
            min_password_length_warn: settings.min_password_length_warn || this.settings.min_password_length_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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

        var passwordPolicy = getAccountPasswordPolicy.data;

        if (!passwordPolicy.MinimumPasswordLength) {
            helpers.addResult(results, 2, 'Password policy does not specify a minimum password length');
        } else if (passwordPolicy.MinimumPasswordLength < config.min_password_length_fail) {
            helpers.addResult(results, 2, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is less than 10 characters', 'global', null, custom);
        } else if (passwordPolicy.MinimumPasswordLength < config.min_password_length_warn) {
            helpers.addResult(results, 1, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is less than 14 characters', 'global', null, custom);
        } else {
            helpers.addResult(results, 0, 'Minimum password length of: ' + passwordPolicy.MinimumPasswordLength + ' is suitable', 'global', null, custom);
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'minPasswordLength';
        var passwordKey = 'MinimumPasswordLength';
        var input = {};
        if (settings.input && settings.input['minPasswordLength']) {
            input[passwordKey] = `${settings.input['minPasswordLength']}`;
        } else {
            input[passwordKey] = '14';

        }

        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};