var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password Expiry',
    category: 'RAM',
    description: 'Ensure that RAM password security settings require password to be expired after 90 days.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to require password to be expired after 90 days.',
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

        if (getPasswordPolicy.data.MaxPasswordAge && 
            getPasswordPolicy.data.MaxPasswordAge > 0 &&
            getPasswordPolicy.data.MaxPasswordAge <= 90) {
            helpers.addResult(results, 0,
                'RAM password security policy requires password to be expired after 90 days', region);
        } else {
            helpers.addResult(results, 2,
                'RAM password security policy does not require password to be expired after 90 days', region);
        }

        callback(null, results, source);
    }
};