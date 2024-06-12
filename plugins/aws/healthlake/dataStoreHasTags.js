var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'HealthLake Data Store Has Tags',
    category: 'AI & ML',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that HealthLake data stores have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify HealthLake data store and add tags.',
    link: '',
    apis: ['HealthLake:listFHIRDatastores', 'ResourceGroupsTaggingAPI:getResources'],
    realtime_triggers: ['healthlake:CreateFHIRDatastore', 'healthlake:DeleteFHIRDatastore'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.healthlake, function(region, rcb){
            var listFHIRDatastores = helpers.addSource(cache, source,
                ['healthlake', 'listFHIRDatastores', region]);

            if (!listFHIRDatastores) return rcb();

            if (listFHIRDatastores.err || !listFHIRDatastores.data) {
                helpers.addResult(results, 3, `Unable to query HealthLake Data Store: ${helpers.addError(listFHIRDatastores)}`, region);
                return rcb();
            }

            if (!listFHIRDatastores.data.length) {
                helpers.addResult(results, 0, 'No HealthLake data stores found', region);
                return rcb();
            }

            const arnList = [];
            for (let datastore of listFHIRDatastores.data){
                if (!datastore.DatastoreArn) continue;
                
                arnList.push(datastore.DatastoreArn);
            }

            helpers.checkTags(cache, 'Healthlake data store', arnList, region, results, settings);
            return rcb();

        }, function(){
            callback(null, results, source);
        });
    }
};