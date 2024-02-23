var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Media Services Managed Identity Enabled',
    category: 'Media Services',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Media Service accounts have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    link: 'https://learn.microsoft.com/en-us/azure/media-services/latest/concept-managed-identities',
    recommended_action: 'Create a new Media service account with managed identity for storage account enabled.',
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

                if (getMediaService.data.identity && getMediaService.data.identity.type 
                && (getMediaService.data.identity.type.toLowerCase() === 'userassigned' ||
                 getMediaService.data.identity.type.toLowerCase() === 'systemassigned')) {

                    helpers.addResult(results, 0, 'Media Service account has managed identity enabled', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service account does not have managed identity enabled', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};