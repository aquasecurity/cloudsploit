var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Media Services Diagnostic Logs Enabled',
    category: 'Media Services',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Media Services have diagnostic logs enabled.',
    more_info: 'Diagnostic logs provide valuable insights into the operation and health of Media Services. By enabling diagnostic logs, you can gather diagnostic data that could be useful to create notification alerts.',
    link: 'https://learn.microsoft.com/en-us/azure/media-services/latest/monitoring/monitor-media-services',
    recommended_action: 'Modify Media Service settings and enable diagnostic logs.',
    apis: ['mediaServices:listAll', 'diagnosticSettings:listByMediaService'],
    realtime_triggers: ['microsoftmedia:mediaservices:write', 'microsoftmedia:mediaservices:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

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

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByMediaService', location, mediaService.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Media Service diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, mediaService.id);
                    continue;
                }


                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'Media Service has diagnostic logs enabled', location, mediaService.id);
                } else {
                    helpers.addResult(results, 2, 'Media Service does not have diagnostic logs enabled', location, mediaService.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
