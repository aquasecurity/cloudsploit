var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password Requires Numbers',
    category: 'RAM',
    description: 'Ensure that RAM password security settings require at least one number.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to require the use of numbers.',
    apis: ['RAM:GetPasswordPolicy'],
    compliance: {
        pci: 'PCI requires a strong password policy. Setting Identity password ' +
             'requirements enforces this policy.'
    },
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

        if (getPasswordPolicy.data.RequireNumbers) {
            helpers.addResult(results, 0,
                'RAM password security policy requires numbers', region);
        } else {
            helpers.addResult(results, 2,
                'RAM password security policy does not require numbers', region);
        }

        callback(null, results, source);
    }
};