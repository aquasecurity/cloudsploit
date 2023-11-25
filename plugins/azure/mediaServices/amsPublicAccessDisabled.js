var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Media Services Public Access Disabled',
    category: 'Media Services',
    domain: 'Network Access Control',
    description: 'Ensure that Microsoft Azure Media Services have public access disabled.',
    more_info: 'Diagnostic logs provide valuable insights into the operation and health of Media Services. By enabling diagnostic logs, you can gather diagnostic data that could be useful to create notification alerts.',
    link: 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/media-services-security-baseline',
    recommended_action: 'Modify the media service network settings and enable private access.',
    apis: ['mediaServices:listAll'],

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
                
                if (mediaService.publicNetworkAccess && mediaService.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0, 'Media Service has public access disabled', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service does not have public access disabled', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};