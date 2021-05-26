var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password No Reuse',
    category: 'RAM',
    description: 'Ensure that RAM password security settings are set to prevent reusing 5 old passwords.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to prevent reusing 5 old passwords.',
    apis: ['RAM:GetPasswordPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var getPasswordPolicy = helpers.addSource(cache, source,
            ['ram', 'GetPasswordPolicy', region]);

        if (!getPasswordPolicy) return callback(null, results, source);

        if (getPasswordPolicy.err || !getPasswordPolicy.data || !Object.keys(getPasswordPolicy.data).length) {
            helpers.addResult(results, 3,
                'Unable to query RAM password policy: ' + helpers.addError(getPasswordPolicy), region);
            return callback(null, results, source);
        }

        if (getPasswordPolicy.data.PasswordReusePrevention >= 5) {
            helpers.addResult(results, 0,
                'RAM password security policy requires to prevent reusing previous 5 or more passwords', region);
        } else {
            helpers.addResult(results, 2,
                'RAM password security policy does not require to prevent reusing previous 5 passwords', region);
        }

        callback(null, results, source);
    }
};