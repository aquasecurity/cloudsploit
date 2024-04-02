var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Media Services Classic API Disabled',
    category: 'Media Services',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that Microsoft Azure Media Services do not have the Classic API enabled.',
    more_info: 'Disabling the Classic API for Azure Media Services is recommended to utilize modern APIs and features. Enabling classic features can enable the use of classic V2 APIs but might disable advanced security features like managed identities.',
    link: 'https://learn.microsoft.com/en-us/azure/media-services/latest/migrate-v-2-v-3-differences-api-access',
    recommended_action: 'Remove Azure Media Services accounts with Classic API enabled and create new accounts without enabling the Classic API.',
    apis: ['mediaServices:listAll', 'mediaServices:get'],
    realtime_triggers: ['microsoftmedia:mediaservices:write', 'microsoftmedia:mediaservices:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.mediaServices, function(location, rcb){
            var mediaServices = helpers.addSource(cache, source, 
                ['mediaServices', 'listAll', location]);

            if (!mediaServices) return rcb();

            if (mediaServices.err || !mediaServices.data) {
                helpers.addResult(results, 3, 'Unable to query for Media Services: ' + helpers.addError(mediaServices), location);
                return rcb();
            }

            if (!mediaServices.data.length) {
                helpers.addResult(results, 0, 'No existing Media Services found', location);
                return rcb();
            }

            for (let mediaService of mediaServices.data) {
                if (!mediaService.id) continue;
  
                var getMediaService = helpers.addSource(cache, source, 
                    ['mediaServices', 'get', location, mediaService.id]);

                if (!getMediaService || getMediaService.err || !getMediaService.data) {
                    helpers.addResult(results, 3, `Unable to query for Media Service data: ${helpers.addError(getMediaService)}`,
                        location, mediaService.id);
                    continue;
                }

                if (getMediaService.data.identity) {
                    helpers.addResult(results, 0, 'Media Service account is not using classic v2 APIs', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service account is using classic v2 APIs', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};