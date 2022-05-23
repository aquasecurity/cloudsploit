var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Users Password Last Used',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Detect users that have not logged in for a period of time and should be deactivated.',
    more_info: 'Having multiple user accounts that have been inactive for a period of time can increase the risk of security attacks and breaches.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingusers.htm',
    recommended_action: 'Delete old user accounts that allow password-based logins and have not been used recently.',
    apis: ['user:list'],
    compliance: {
        pci: 'PCI requires that all user credentials are rotated every 90 days. If the user password has not been used in the last 90 days, the user should be deactivated.'
    },
    settings: {
        identity_users_password_last_used_fail: {
            name: 'Users Password Last Used Fail',
            description: 'Return a failing result when users with password logins exceed this number of days without being used',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '180'
        }
    },


    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var config = {
            identity_users_password_last_used_fail: parseInt(settings.identity_users_password_last_used_fail || this.settings.identity_users_password_last_used_fail.default)
        };

        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        if (!users) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for user MFA status: ' + helpers.addError(users));
            return callback(null, results, source);
        }

        if (users.data.length < 2) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }


        var found = false;

        users.data.forEach(user => {
            var returnCode, returnMsg, daysAgo;

            if (user.lastSuccessfulLoginTime) {
                daysAgo = helpers.daysBetween(new Date(), new Date(user.lastSuccessfulLoginTime));
                returnMsg = `User's last successful login was ${daysAgo} days ago`;
            } else if (user.timeCreated) {
                daysAgo = helpers.daysBetween(new Date(), new Date(user.timeCreated));
                returnMsg = `User was created ${daysAgo} days ago but never logged in`;
            }

            if (!isNaN(daysAgo)) {
                
                if (daysAgo > config.identity_users_password_last_used_fail) {
                    returnCode = 2;
                } else {
                    returnCode = 0;
                }

                helpers.addResult(results, returnCode, returnMsg, 'global', user.id);

                found = true;
            }
        });

        if (!found) {
            helpers.addResult(results, 0, 'No users with password logins found');
        }

        callback(null, results, source);
    }
};
