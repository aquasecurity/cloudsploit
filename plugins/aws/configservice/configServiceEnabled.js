var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Config Service Enabled',
    category: 'ConfigService',
    description: 'Ensures the AWS Config Service is enabled to detect changes to account resources',
    more_info: 'The AWS Config Service tracks changes to a number of resources in an AWS account and is invaluable in determining how account changes affect other resources and in recovery in the event of an account intrusion or accidental configuration change.',
    recommended_action: 'Enable the AWS Config Service for all regions and resources in an account. Ensure that it is properly recording and delivering logs.',
    link: 'https://aws.amazon.com/config/details/',
    apis: ['ConfigService:describeConfigurationRecorders', 'ConfigService:describeConfigurationRecorderStatus'],
    compliance: {
        pci: 'PCI requires the development and maintenance of secure applications. ' +
             'While ConfigService cannot assist in developing secure applications, ' +
             'it can be used to detect application and environment changes that ' +
             'could introduce security risks.',
        cis1: '2.5 Ensure AWS Config is enabled in all regions'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var globalServicesMonitored = false;

        async.each(regions.configservice, function(region, rcb){
            var describeConfigurationRecorders = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorders', region]);

            var describeConfigurationRecorderStatus = helpers.addSource(cache, source,
                ['configservice', 'describeConfigurationRecorderStatus', region]);

            if (describeConfigurationRecorders &&
                describeConfigurationRecorders.data &&
                describeConfigurationRecorders.data &&
                describeConfigurationRecorders.data[0] &&
                describeConfigurationRecorders.data[0].recordingGroup &&
                describeConfigurationRecorders.data[0].recordingGroup.includeGlobalResourceTypes) {
                globalServicesMonitored = true;
            }

            if (!describeConfigurationRecorders) return rcb();

            // TODO: loop through ALL config recorders
            // TODO: add resource ARN for config recorders

            if (!describeConfigurationRecorderStatus ||
                describeConfigurationRecorderStatus.err ||
                !describeConfigurationRecorderStatus.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Config Service status: ' + helpers.addError(describeConfigurationRecorderStatus), region);
                return rcb();
            }

            if (describeConfigurationRecorderStatus.data[0]) {
                var crs = describeConfigurationRecorderStatus.data[0];

                if (crs.recording) {
                    if (crs.lastStatus &&
                        (crs.lastStatus.toUpperCase() == 'SUCCESS' ||
                         crs.lastStatus.toUpperCase() == 'PENDING')) {
                        helpers.addResult(results, 0,
                            'Config Service is configured, recording, and delivering properly', region);
                    } else {
                        helpers.addResult(results, 1,
                            'Config Service is configured, and recording, but not delivering properly', region);
                    }
                } else {
                    helpers.addResult(results, 2, 'Config Service is configured but not recording', region);
                }

                return rcb();
            }

            helpers.addResult(results, 2, 'Config Service is not configured', region);

            rcb();
        }, function(){
            if (!globalServicesMonitored) {
                helpers.addResult(results, 2, 'Config Service is not monitoring global services');
            } else {
                helpers.addResult(results, 0, 'Config Service is monitoring global services');
            }

            callback(null, results, source);
        });
    }
};