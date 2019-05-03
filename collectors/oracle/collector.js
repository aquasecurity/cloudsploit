/*********************
 Collector - The collector will query Oracle's APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - OracleConfig: Required Authentication parameters for Oracle's REST API.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["East US", "West US"],
     "api_calls": ["EC2:describeInstances", "S3:listBuckets"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');

var helpers = require(__dirname + '/../../helpers/oracle');

const regionSubscriptionService = { name: 'regionSubscription', call: 'list', region: helpers.regions(false).default };

var globalServices = [
    'core'
];

var calls = {
    regionSubscription: {
        list: {
            api: "iam",
            filterKey: ['tenancyId'],
            filterValue: ['tenancyId'],
        }
    },
    vcn: {
        list: {
            api: "core",
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    publicIp: {
        list: {
            api: "core",
            filterKey: ['compartmentId', 'scope'],
            filterValue: ['compartmentId', 'REGION'],
            filterLiteral: [false, true],
        }
    },
    instance: {
        list: {
            api: "core",
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    }
};

// Important Note: All relies must be passed in an array format []
var postcalls = {
    vcn: {
        get: {
            api: "core",
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['vcnId'],
            filterValue: ['id'],
        }
    },
    subnet: {
        list: {
            api: "core",
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'vcnId'],
            filterValue: ['compartmentId', 'id'],
        }
    },
    securityList: {
        list: {
            api: "core",
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'vcnId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    }
};

var finalcalls = {};

var postfinalcalls = {};

var collection = {};

var processCall = function(OracleConfig, settings, regions, call, service, serviceCb) {
    // Loop through each of the service's functions
    async.eachOfLimit(call, 10, function (callObj, callKey, callCb) {
        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
        if (!collection[service][callKey]) collection[service][callKey] = {};

        async.eachLimit(regions[service], helpers.MAX_REGIONS_AT_A_TIME, function (region, regionCb) {
            if (settings.skip_regions &&
                settings.skip_regions.indexOf(region) > -1 &&
                globalServices.indexOf(service) === -1) return regionCb();

            // Ignore regions we are not subscribed to
            if (collection[regionSubscriptionService.name] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(
                    r=>r.regionName==region) &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(
                    r=>r.regionName==region).length==0
            ){
                return regionCb();
            }

            if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

            if (callObj.reliesOnService) {
                if (!callObj.reliesOnService.length) return regionCb();
                // Ensure multiple pre-requisites are met
                for (reliedService in callObj.reliesOnService){
                    if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                    if (callObj.reliesOnService[reliedService] &&
                        (!collection[callObj.reliesOnService[reliedService]] ||
                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data ||
                            !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data.length)) return regionCb();
                }
            }

            var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
            LocalOracleConfig.region = region;
            LocalOracleConfig.service = service;

            var executor = new helpers.OracleExecutor(LocalOracleConfig);
            executor.run(collection, service, callObj, callKey, function(err, data){
                if (err) {
                    collection[service][callKey][region].err = err;
                }

                if (!data) return regionCb();

                collection[service][callKey][region].data = data;

                if (callObj.rateLimit) {
                    setTimeout(function(){
                        regionCb();
                    }, callObj.rateLimit);
                } else {
                    regionCb();
                }
            });
        }, function () {
            callCb();
        });
    }, function () {
        serviceCb();
    });
};

var getRegionSubscription = function(OracleConfig, settings, calls, service, callKey, region, serviceCb) {

    var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
    LocalOracleConfig.region = region;
    LocalOracleConfig.service = service;

    if (!collection[service]) collection[service] = {};
    if (!collection[service][callKey]) collection[service][callKey] = {};
    if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

    var executor = new helpers.OracleExecutor(LocalOracleConfig);
    executor.run(collection, service, calls[service][callKey], callKey, function(err, data){
        if (err) {
            collection[service][callKey][region].err = err;
        }

        if (!data) return regionCb();

        collection[service][callKey][region].data = data;

        serviceCb();
    });
};

// Loop through all of the top-level collectors for each service
var collect = function (OracleConfig, settings, callback) {
    OracleConfig.maxRetries = 5;
    OracleConfig.retryDelayOptions = {base: 300};

    var settings = settings;
    var regions = helpers.regions(settings.govcloud);

    getRegionSubscription(OracleConfig, settings, calls, regionSubscriptionService.name, regionSubscriptionService.call, regionSubscriptionService.region, function () {
        async.eachOfLimit(calls, 10, function (call, service, serviceCb) {
            var service = service;
            if (!collection[service]) collection[service] = {};

            processCall(OracleConfig, settings, regions, call, service, function () {
                serviceCb();
            });
        }, function () {
            // Now loop through the follow up calls
            async.eachOfLimit(postcalls, 10, function (postCall, service, serviceCb) {
                var service = service;
                if (!collection[service]) collection[service] = {};

                processCall(OracleConfig, settings, regions, postCall, service, function () {
                    serviceCb();
                });
            }, function () {
                //console.log(JSON.stringify(collection, null, 2));
                callback(null, collection);
            });
        }, function () {
            //console.log(JSON.stringify(collection, null, 2));
            callback(null, collection);
        });
    });
};

module.exports = collect;