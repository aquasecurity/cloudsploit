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
     'skip_regions': [', '],
     'api_calls': ['EC2:describeInstances', 'S3:listBuckets']
 }
 - callback: Function to call when the collection is complete
 *********************/

var async = require('async');

var helpers = require(__dirname + '/../../helpers/oracle');

const regionSubscriptionService = {name: 'regionSubscription', call: 'list', region: helpers.regions(false).default};

var globalServices = [
    'core'
];

var calls = {
    // Do not use regionSubscription in Plugins
    // It will be loaded automatically by the
    // Oracle Collector
    regionSubscription: {
        list: {
            api: 'iam',
            filterKey: ['tenancyId'],
            filterValue: ['tenancyId'],
        }
    },
    vcn: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    publicIp: {
        list: {
            api: 'core',
            filterKey: ['compartmentId', 'scope'],
            filterValue: ['compartmentId', 'REGION'],
            filterLiteral: [false, true],
        }
    },
    instance: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    loadBalancer: {
        list: {
            api: 'loadBalance',
            restVersion: '/20170115',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId']
        }
    },
    user: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    authenticationPolicy: {
        get: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['tenancyId'],
            filterConfig: [true]
        }
    },
    namespace: {
        get: {
            api: 'objectStore',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '',
            filterConfig: [true]
        }
    },
    group: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    exportSummary: {
        list: {
            api: 'fileStorage',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20171215',
        }
    },
    mountTarget: {
        list: {
            api: 'fileStorage',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20171215',
        }
    },
    // Do not use compartment:get in Plugins
    // It will be loaded automatically by the
    // Oracle Collector
    compartment: {
        get: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    waasPolicy: {
        list: {
            api: 'waas',
            restVersion: '/20181116',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    policy: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    dbHome: {
        list: {
            api: 'database',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    instancePool: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    autoscaleConfiguration: {
        list: {
            api: 'autoscale',
            restVersion: '/20181001',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    bootVolume: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    volume: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    availabilityDomain: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    bootVolumeBackup: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    volumeBackup: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    bootVolumeAttachment: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
    },
    volumeBackupPolicy: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    volumeGroup: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    volumeGroupBackup: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    configuration: {
        get: {
            api: 'audit',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            filterConfig: [true]
        }
    },
    networkSecurityGroup: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    dbSystem: {
        list: {
            api: 'database',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    }
};

// Important Note: All relies must be passed in an array format []
var postcalls = {
    vcn: {
        get: {
            api: 'core',
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['vcnId'],
            filterValue: ['id'],
        }
    },
    subnet: {
        list: {
            api: 'core',
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'vcnId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    securityList: {
        list: {
            api: 'core',
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'vcnId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    userGroupMembership: {
        list: {
            api: 'iam',
            reliesOnService: ['group'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'groupId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    bucket: {
        list: {
            api: 'objectStore',
            reliesOnService: ['namespace'],
            reliesOnCall: ['get'],
            filterKey: ['compartmentId','namespaceName'],
            filterValue: ['compartmentId','namespaceName'],
            filterConfig: [true, false],
            restVersion: '',
            limit: 900
        }
    },
    waasPolicy: {
        get: {
            api: 'waas',
            restVersion: '/20181116',
            reliesOnService: ['waasPolicy'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'waasPolicyId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    database: {
        list: {
            api: 'database',
            restVersion: '/20160918',
            reliesOnService: ['dbHome'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'dbHomeId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    securityRule: {
        list: {
            api: 'core',
            reliesOnService: ['networkSecurityGroup'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'networkSecurityGroupId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    volumeBackupPolicyAssignment: {
        volume: {
            api: 'core',
            reliesOnService: ['volume'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'assetId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        },
        bootVolume: {
            api: 'core',
            reliesOnService: ['bootVolume'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'assetId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
};

// Important Note: All relies must be passed in an array format []
var finalcalls = {
    bucket: {
        get: {
            api: 'objectStore',
            reliesOnService: ['bucket','namespace'],
            reliesOnCall: ['list', 'get'],
            filterKey: ['bucketName', 'namespaceName'],
            filterValue: ['name','namespace'],
            restVersion: '',
        }
    },
    exprt: {
        get: {
            api: 'fileStorage',
            reliesOnService: ['exportSummary'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'exportId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
            restVersion: '/20171215',
        }
    },
    preAuthenticatedRequest: {
        list: {
            api: 'objectStore',
            reliesOnService: ['bucket','namespace'],
            reliesOnCall: ['list', 'get'],
            filterKey: ['bucketName', 'namespaceName'],
            filterValue: ['name','namespace'],
            restVersion: ''
        }
    },
};


var processCall = function(OracleConfig, collection, settings, regions, call, service, serviceCb) {
    // Loop through each of the service's functions
    async.eachOfLimit(call, 10, function(callObj, callKey, callCb) {
        if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
        if (!collection[service][callKey]) collection[service][callKey] = {};

        async.eachLimit(regions[service], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
            if (settings.skip_regions &&
                settings.skip_regions.indexOf(region) > -1 &&
                globalServices.indexOf(service) === -1) return regionCb();

            // Ignore regions we are not subscribed to
            if (collection[regionSubscriptionService.name] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region] &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(r => r.regionName == region) &&
                collection[regionSubscriptionService.name][regionSubscriptionService.call][regionSubscriptionService.region].data.filter(r => r.regionName == region).length == 0) {
                return regionCb();
            }
            if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

            if (callObj.reliesOnService) {
                if (!callObj.reliesOnService.length) return regionCb();
                // Ensure multiple pre-requisites are met
                for (var reliedService in callObj.reliesOnService) {
                    if (callObj.reliesOnService[reliedService] && !collection[callObj.reliesOnService[reliedService]]) return regionCb();

                    if (callObj.reliesOnService[reliedService] &&
                        (!collection[callObj.reliesOnService[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region] ||
                        !collection[callObj.reliesOnService[reliedService]][callObj.reliesOnCall[reliedService]][region].data)) return regionCb();
                }
            }

            var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
            LocalOracleConfig.region = region;
            LocalOracleConfig.service = service;


            var executor = new helpers.OracleExecutor(LocalOracleConfig);
            executor.run(collection, service, callObj, callKey, function(err, data) {
                if (err && err.length) {
                    collection[service][callKey][region].err = err;
                }

                if (!data) return regionCb();
                collection[service][callKey][region].data = data;

                if (callObj.rateLimit) {
                    setTimeout(function() {
                        regionCb();
                    }, callObj.rateLimit);
                } else {
                    regionCb();
                }
            });
        }, function() {
            callCb();
        });
    }, function() {
        serviceCb();
    });
};

var getRegionSubscription = function(OracleConfig, collection, settings, calls, service, callKey, region, serviceCb) {

    var LocalOracleConfig = JSON.parse(JSON.stringify(OracleConfig));
    LocalOracleConfig.region = region;
    LocalOracleConfig.service = service;

    if (!collection[service]) collection[service] = {};
    if (!collection[service][callKey]) collection[service][callKey] = {};
    if (!collection[service][callKey][region]) collection[service][callKey][region] = {};

    var executor = new helpers.OracleExecutor(LocalOracleConfig);
    executor.run(collection, service, calls[service][callKey], callKey, function(err, data) {
        if (err) {
            collection[service][callKey][region].err = err;
        }

        if (!data) return serviceCb();

        collection[service][callKey][region].data = data;

        serviceCb();
    });
};

// Loop through all of the top-level collectors for each service
var collect = function(OracleConfig, settings, callback) {
    var collection = {};

    OracleConfig.maxRetries = 5;
    OracleConfig.retryDelayOptions = {base: 300};

    var regions = helpers.regions(settings.govcloud);

    getRegionSubscription(OracleConfig, collection, settings, calls, regionSubscriptionService.name, regionSubscriptionService.call, regionSubscriptionService.region, function() {
        async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
            if (!collection[service]) collection[service] = {};

            processCall(OracleConfig, collection, settings, regions, call, service, function() {
                serviceCb();
            });
        }, function() {
            // Now loop through the follow up calls
            async.eachOfLimit(postcalls, 10, function(postCall, service, serviceCb) {
                if (!collection[service]) collection[service] = {};

                processCall(OracleConfig, collection, settings, regions, postCall, service, function() {
                    serviceCb();
                });
            }, function() {
                // Now loop through the follow up calls
                async.eachOfLimit(finalcalls, 10, function(finalCall, service, serviceCb) {
                    if (!collection[service]) collection[service] = {};

                    processCall(OracleConfig, collection, settings, regions, finalCall, service, function() {
                        serviceCb();
                    });
                }, function() {
                    //console.log(JSON.stringify(collection, null, 2));
                    callback(null, collection);
                });
            }, function() {
                //console.log(JSON.stringify(collection, null, 2));
                callback(null, collection);
            });
        }, function() {
            //console.log(JSON.stringify(collection, null, 2));
            callback(null, collection);
        });
    });
};

module.exports = collect;