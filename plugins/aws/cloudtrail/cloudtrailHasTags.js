var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'CloudTrail Has Tags',
    category: 'CloudTrail',
    domain: 'Compliance',
    severity: 'Low',
    description: 'Ensure that AWS CloudTrail trails have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify CloudTrail trails and add tags.',
    link: 'https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AddTags.html',
    apis: ['CloudTrail:describeTrails', 'CloudTrail:listTags'],
    realtime_triggers: ['cloudtrail:CreateTrail', 'cloudtrail:AddTags','cloudtrail:RemoveTags','cloudtrail:DeleteTrail'],

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
                    `Unable to query for CloudTrail trails: ${helpers.addError(describeTrails)}`, region);
                return rcb();
            }

            if (!describeTrails.data.length) {
                helpers.addResult(results, 0, 'CloudTrail is not enabled', region);
                return rcb();
            }

            for (let trail of describeTrails.data){
                if (!trail.TrailARN || (trail.HomeRegion && trail.HomeRegion.toLowerCase() !== region)) continue;
                // Skip CloudSploit-managed events bucket
                if (trail.TrailARN == helpers.CLOUDSPLOIT_EVENTS_BUCKET) continue;
                
                let listTags = helpers.addSource(cache, source,
                    ['cloudtrail', 'listTags', region, trail.TrailARN]);

                if (!listTags || listTags.err || !listTags.data || !listTags.data.ResourceTagList || !listTags.data.ResourceTagList.length) {
                    helpers.addResult(results, 3,
                        `Unable to list trail tags: ${helpers.addError(listTags)}`, region);
                    continue;
                }

                if (!listTags.data.ResourceTagList[0].TagsList || 
                    !listTags.data.ResourceTagList[0].TagsList.length){
                    helpers.addResult(results, 2, 'CloudTrail trail does not have tags', region, trail.TrailARN);
                } else {
                    helpers.addResult(results, 0, 'CloudTrail trail has tags', region, trail.TrailARN);
                }
            }    
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};             