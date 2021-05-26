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
            
            if (getAccessKey.err || !getAccessKey.data) {
                helpers.addResult(results, 3,
                    'Unable to query user access keys' + helpers.addError(getAccessKey), region);
                continue;
            }
            
            var resource = helpers.createArn('ram', accountId, 'user', user.UserName);
            if (getAccessKey.data.AccessKeys && getAccessKey.data.AccessKeys.AccessKey && getAccessKey.data.AccessKeys.AccessKey.length) {
                var accessKeysList = getAccessKey.data.AccessKeys.AccessKey
                for (var accessKey of accessKeysList) {
                    if (accessKey.Status == 'Active') {
                        let createDate = accessKey.CreateDate;
                        var currentDate = new Date();
                        var createDateFormat = new Date(createDate);
        
                        var diffInDays = helpers.daysBetween(currentDate, createDateFormat);
                        if (diffInDays >= 90) {
                            helpers.addResult(results, 2,
                                `RAM user access key is not rotated for ${diffInDays} days`, region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                `RAM user access key is rotated for ${diffInDays} days`, region, resource);
                        }
                    }
                }
            } else {
                helpers.addResult(results, 0,
                    'RAM user does not have any active access keys', region, resource);
            }
        }

        callback(null, results, source);
    }
};