var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM User Account In Use',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensure that IAM user accounts are not being actively used.',
    more_info: 'IAM users, roles, and groups should not be used for day-to-day account management.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html',
    recommended_action: 'Delete IAM user accounts which are being actively used.',
    apis: ['IAM:generateCredentialReport'],
    settings: {
        iam_user_account_in_use_days: {
            name: 'IAM User Account In Use Days',
            description: 'Return a failing result when an IAM user account has been used within this many days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '15'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            iam_user_account_in_use_days: parseInt(settings.iam_user_account_in_use_days || this.settings.iam_user_account_in_use_days.default)
        };
        const custom = helpers.isCustom(settings, this.settings);

        const results = [];
        const source = {};

        const region = helpers.defaultRegion(settings);

        const generateCredentialReport = helpers.addSource(cache, source,
            ['iam', 'generateCredentialReport', region]);
        
        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3,
                'Unable to query IAM users: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        let found = false;

        generateCredentialReport.data.forEach(user => {
            if (user && user.user !== '<root_account>') {
                found = true;

                var accessDates = [];

                if (user.password_last_used && user.password_last_used !== 'no_information') accessDates.push(user.password_last_used);

                if (user.access_key_1_last_used_date && user.access_key_1_last_used_date != 'N/A') accessDates.push(user.access_key_1_last_used_date);

                if (user.access_key_2_last_used_date && user.access_key_2_last_used_date != 'N/A') accessDates.push(user.access_key_2_last_used_date);

                if (!accessDates.length) {
                    helpers.addResult(results, 0, 'IAM user has not been used', 'global', user.arn);
                } else {
                    const currentDate = new Date();
                    const loginDate = new Date(helpers.mostRecentDate(accessDates));
                    const difference = helpers.daysBetween(loginDate, currentDate);
                    const resultCode = ( difference < config.iam_user_account_in_use_days) ? 2: 0;

                    helpers.addResult(results, resultCode,
                        'IAM user was last used ' + difference + ' days ago',
                        'global', user.arn, custom);
                }
            }
        });

        if (!found) {
            helpers.addResult(results, 0, 'No IAM users found', 'global');
        }

        callback(null, results, source);
    }
};
