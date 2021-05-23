var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Access Keys Rotation',
    category: 'RAM',
    description: 'Ensure that user access keys are rotated after regular interval of time.',
    more_info: 'Access keys needs to be rotated for the sake of security.',
    link: 'https://www.alibabacloud.com/help/doc-detail/152682.htm',
    recommended_action: 'Rotate the access keys every 90 days or less.',
    apis: ['RAM:ListUsers', 'RAM:ListAccessKeys', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);
        var listUsers = helpers.addSource(cache, source, 
            ['ram', 'ListUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query RAM users' + helpers.addError(listUsers), region);
            return callback(null, results, source);
        }

        if (!listUsers.data.length) {
            helpers.addResult(results, 0, 'No RAM users found', region);
            return callback(null, results, source);
        }

        for (var user of listUsers.data) {
            if (!user.UserName) continue;

            var getAccessKey = helpers.addSource(cache, source,
                ['ram', 'ListAccessKeys', region, user.UserName]);
            
            var resource = helpers.createArn('ram', accountId, 'user', user.UserName);
            var accessKey = getAccessKey.data.AccessKeys.AccessKey.find(key => key.Status && key.Status == 'Active');

            if (accessKey) {
                let createDate = accessKey.CreateDate;
                var currentDate = new Date();
                var createDateFormat = new Date(createDate);

                var diffInDays = helpers.daysBetween(currentDate, createDateFormat);
                if (diffInDays >= 90) {
                    helpers.addResult(results, 2,
                        'RAM user access keys are not rotated every 90 days or less ', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'RAM user access keys are rotated every 90 days or less', region, resource);
                }
            } else {
                helpers.addResult(results, 0,
                    'RAM user access keys does not exist ', region, resource);
            }
        }

        callback(null, results, source);
    }
};