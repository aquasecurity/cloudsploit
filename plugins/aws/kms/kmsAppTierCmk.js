var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier KMS Customer Master Key (CMK)',
    category: 'KMS',
    description: 'Ensures that there is one Amazon KMS Customer Master Key (CMK) present in the account for App-Tier resources.',
    more_info: 'Amazon KMS should have Customer Master Key (CMK) for App-Tier to protect data in transit.',
    recommended_action: 'Create a Customer Master Key (CMK) with App-Tier tag',
    link: 'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
    apis: ['KMS:listKeys', 'KMS:listResourceTags'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by KMS Customer Master Keys to indicate App-Tier CMK',
            regex: '^.*$',
            default: 'app_tier'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {
            app_tier_tag_key: settings.app_tier_tag_key || this.settings.app_tier_tag_key.default
        };
        var appTierKmsKey = false;

        async.each(regions.kms, function(region, rcb){
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`,
                    region);
                return rcb();
            }

            if (!listKeys.data.length) {
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();
            }

            async.each(listKeys.data, function(kmsKey, kcb){
                if(!appTierKmsKey) {
                    var listResourceTags = helpers.addSource(cache, source,
                        ['kms', 'listResourceTags', region, kmsKey.KeyId]);

                    if (!listResourceTags || listResourceTags.err || !listResourceTags.data || !listResourceTags.data.Tags || !listResourceTags.data.Tags.length) {
                        helpers.addResult(results, 3,
                            `Unable to describe resource tags: ${helpers.addError(listResourceTags)}`,
                            region, kmsKey.KeyArn);
                        return kcb();
                    }

                    var tags = listResourceTags.data;
                    if(tags.Tags && tags.Tags.length) {
                        for(var i in tags.Tags) {
                            if(tags.Tags[i].TagKey === config.app_tier_tag_key) {
                                appTierKmsKey = true;
                                break;
                            }
                        }
                    }
                }

                kcb();
            }, function(){
                if(appTierKmsKey) {
                    helpers.addResult(results, 0,
                        'App-Tier KMS Customer Master key is present in the account',
                        region);
                } else {
                    helpers.addResult(results, 2,
                        'App-Tier KMS Customer Master key is not present in the account',
                        region);
                }

                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};