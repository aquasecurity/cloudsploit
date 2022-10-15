var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail has tags',
    category: 'CloudTrail',
    domain: 'Compliance',
    description: 'Ensure that Cloud trails have tags',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify ClouTrail trails and tags',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AddTags.html',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:listTags'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.cloudtrail, function(region, rcb){

            var describeTrails = helpers.addSource(cache, source,
                ['cloudtrail', 'describeTrails', region]);

            if (!describeTrails) return rcb();

            if (describeTrails.err || !describeTrails.data) {
                helpers.addResult(results, 3,
                    `Unable to query for trails: ${helpers.addError(describeTrails)}`, region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'CloudTrail is not enabled', region);
                return rcb();
            }
            for (let trail of describeTrails.data){
                if (!trail.TrailARN) return rcb();
                
                let listTags = helpers.addSource(cache, source,
                    ['cloudtrail', 'listTags', region, trail.TrailARN]);

                if (listTags.err || !listTags.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for listTags api: ${helpers.addError(listTags)}`, region);
                    return rcb();
                }

                if (!listTags.data.ResourceTagList || 
                !listTags.data.ResourceTagList[0].TagsList || 
                !listTags.data.ResourceTagList[0].TagsList.length){
                    helpers.addResult(results, 2, 'Cloudtrail does not have tags associated.', region, trail.TrailARNs);
                } else {
                    helpers.addResult(results, 0, 'Cloudtrail have tags associated.', region, trail.TrailARNs) ;
                }
            }    
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};             