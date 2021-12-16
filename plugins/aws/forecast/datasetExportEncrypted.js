var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Forecast Dataset Export Encrypted',
    category: 'Forecast',
    domain: 'Content Delivery',
    description: 'Ensure that AWS Forecast exports have encryption enabled before they are being saved on S3.',
    more_info: 'In AWS Forecast, you can save forecast reports on S3 in CSV format. Make sure to encrypt these export before writing them to the bucket in order to follow your organizations\'s security and compliance requirements.',
    recommended_action: 'Create Forecast exports with encryption enabled',
    link: 'https://docs.aws.amazon.com/forecast/latest/dg/howitworks-forecast.html',
    apis: ['ForecastService:listForecastExportJobs', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {},

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.forecastservice, function(region, rcb){
            var listForecastExportJobs = helpers.addSource(cache, source,
                ['forecastservice', 'listForecastExportJobs', region]);

            if (!listForecastExportJobs) return rcb();

            if (listForecastExportJobs.err || !listForecastExportJobs.data) {
                helpers.addResult(results, 3,
                    'Unable to query forecast exports: ' + helpers.addError(listForecastExportJobs), region);
                return rcb();
            }

            if (!listForecastExportJobs.data.length) {
                helpers.addResult(results, 0, 'No forecast export found', region);
                return rcb();
            }

            for (let forecastExportJob of listForecastExportJobs.data) {
                let { S3Config } = forecastExportJob.Destination;
                let resource = forecastExportJob.ForecastExportJobArn;

                if (S3Config.KMSKeyArn) {
                    helpers.addResult(results, 0,
                        `Forecast Dataset Export is with ${S3Config.KMSKeyArn}`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Forecast Dataset Export is not encrypted', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
