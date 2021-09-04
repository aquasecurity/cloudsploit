var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Documents Public Access',
    category: 'SSM',
    description: 'Ensures SSM documents do not have public access.',
    more_info: 'Public documents can be viewed by all AWS accounts. To prevent unwanted access to your documents, turn on the block public access sharing setting.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-share-block.html',
    recommended_action: 'Update the SSM document permissions to not allow public access.',
    apis: ['SSM:getServiceSetting', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        
        const regions = helpers.regions(settings);
        const acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        const accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        for (const region of regions.ssm) {
            const resource = 'arn:' + awsOrGov + ':ssm:' + region + ':' + accountId + ':servicesetting/ssm/documents/console/public-sharing-permission';

            const listDocuments = helpers.addSource(cache, source,
                ['ssm', 'getServiceSetting', region]);
            if (!listDocuments) continue;

            if (listDocuments.err || !listDocuments.data) {
                helpers.addResult(results, 3,
                    'Unable to query SSM service settings: ' + helpers.addError(listDocuments), region, resource);
                continue;
            }
            if (!listDocuments.data.SettingValue) {
                helpers.addResult(results, 2, 'SSM document is publicly accessible', region, resource);
                continue;    
            }

            const isPublic = (listDocuments.data.SettingValue.toUpperCase() == 'ENABLE') ? true : false;
            helpers.addResult(results, isPublic ? 2 :0,
                `SSM document is ${isPublic ? '' : 'not '}publicly accessible`, region, resource);    
        }
        callback(null, results, source);
    }
};
