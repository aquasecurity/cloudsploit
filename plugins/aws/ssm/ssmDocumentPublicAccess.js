var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Documents Public Access',
    category: 'SSM',
    description: 'Ensures SSM documents do not have public access.',
    more_info: '',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-share-block.html',
    recommended_action: 'Update the SSM document permissions to not allow public access.',
    apis: ['SSM:listDocuments', 'SSM:describeDocument', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        const listDocuments = helpers.addSource(cache, source,
            ['ssm', 'listDocuments', region]);

        callback(null, results, source)
    }
}