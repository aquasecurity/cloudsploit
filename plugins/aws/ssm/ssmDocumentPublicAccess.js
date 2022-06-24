var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Documents Public Access',
    category: 'SSM',
    domain: 'Identity Access and Management',
    description: 'Ensure that SSM service has block public sharing setting enabled.',
    more_info: 'Public documents can be viewed by all AWS accounts. To prevent unwanted access to your documents, turn on the block public access sharing setting.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-share-block.html',
    recommended_action: 'Enable block public sharing setting under SSM  documents preferences.',
    apis: ['SSM:getServiceSetting', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        const acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        const accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        for (const region of regions.ssm) {
            const getServiceSetting = helpers.addSource(cache, source,
                ['ssm', 'getServiceSetting', region]);

            if (!getServiceSetting) continue;

            const resource = 'arn:' + awsOrGov + ':ssm:' + region + ':' + accountId + ':servicesetting/ssm/documents/console/public-sharing-permission';

            if (getServiceSetting.err || !getServiceSetting.data) {
                helpers.addResult(results, 3,
                    'Unable to query SSM service settings: ' + helpers.addError(getServiceSetting), region, resource);
                continue;
            }

            const isPublic = (getServiceSetting.data.SettingValue && getServiceSetting.data.SettingValue.toUpperCase() == 'ENABLE') ?
                true : false;
            helpers.addResult(results, isPublic ? 2 :0,
                `SSM service has block public sharing ${isPublic ? 'enabled' : 'disabled'} for SSM documents`, region, resource);    
        }

        callback(null, results, source);
    }
};