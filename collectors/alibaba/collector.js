/*********************
Collector - The collector will query Alibaba APIs for the information required
to run the CloudSploit scans. This data will be returned in the callback
as a JSON object.

Arguments:
- AlibabaConfig: If using an access key/secret, pass in the config object. Pass null if not.
- settings: custom settings for the scan. Properties:
- skip_regions: (Optional) List of regions to skip
- api_calls: (Optional) If provided, will only query these APIs.
- Example:
{
    "skip_regions": ["cn-hangzhou", "cn-shanghai"],
    "api_calls": ["ECS:DescribeInstances", "VPC:DescribeFlowLogs"]
}
- callback: Function to call when the collection is complete
*********************/

var alicloud = require('@alicloud/pop-core');
var async = require('async');
var helpers = require(__dirname + '/../../helpers/alibaba');

var regions = helpers.regions();

var regionEndpointMap = {};

var globalServices = [
    'RAM'
];
 
var calls = {
    ECS: {
        DescribeInstances: {
            property: 'Instances',
            subProperty: 'Instance',
            paginate: 'NextToken',
            apiVersion: '2014-05-26'
        }
    },
    RAM: {
        ListPolicies: {
            property: 'Policies',
            subProperty: 'Policy',
            apiVersion: '2015-05-01',
            paginate: 'Marker'
        },
        ListUsers: {
            property: 'Users',
            subProperty: 'User',
            apiVersion: '2015-05-01',
            paginate: 'Marker'
        }
    },
    GBDB: {
        DescribeDBInstances: {
            property: 'Items',
            subProperty: 'DBInstance',
            apiVersion: '2015-05-01',
            paginate: 'Pages'
        }
    },
    VPC: {
        DescribeVpcs: {
            property: 'Vpcs',
            subProperty: 'Vpc',
            apiVersion: '2016-04-28',
            paginate: 'Pages'
        },
        DescribeVSwitches: {
            property: 'VSwitches',
            subProperty: 'VSwitch',
            apiVersion: '2016-04-28',
            paginate: 'Pages'
        }
    },
    RDS: {
        DescribeDBInstances: {
            property: 'Items',
            subProperty: 'DBInstance',
            apiVersion: '2014-08-15',
            paginate: 'Pages'
        }
    },
    POLARDB: {
        DescribeDBClusters: {
            property: 'Items',
            subProperty: 'DBCluster',
            apiVersion: '2017-08-01',
            paginate: 'Pages'
        }
    }
};

var postcalls = [
    {
        ECS: {
            DescribeInstanceStatus: {
                reliesOnService: 'ecs',
                reliesOnCall: 'DescribeInstances',
                filterKey: ['InstanceId'],
                filterValue: ['InstanceId'],
                apiVersion: '2014-05-26'
            }
        },
        RAM: {
            GetPolicy: {
                reliesOnService: 'ram',
                reliesOnCall: 'ListPolicies',
                filterKey: ['PolicyName', 'PolicyType'],
                filterValue: ['PolicyName', 'PolicyType'],
                resultFilter: 'DefaultPolicyVersion',
                apiVersion: '2015-05-01'
            },
            GetUser: {
                reliesOnService: 'ram',
                reliesOnCall: 'ListUsers',
                filterKey: ['UserName'],
                filterValue: ['UserName'],
                resultFilter: 'User',
                apiVersion: '2015-05-01'
            }
        }
    }
];

var collect = function(AlibabaConfig, settings, callback) {
    if (settings.gather) {
        return callback(null, calls, postcalls);
    }

    var collection = {};

    async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
        let serviceLower = service.toLowerCase();
        if (!collection[serviceLower]) collection[serviceLower] = {};

        async.eachOfLimit(call, 15, function(callObj, callKey, callCb) {
            if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
            if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

            let callRegions = regions[serviceLower];
            let requestOption = { method: callObj.method || 'POST' };

            async.eachLimit(callRegions, helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                if (settings.skip_regions &&
                    settings.skip_regions.indexOf(region) > -1 &&
                    globalServices.indexOf(service) === -1) return regionCb();
                if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                let LocalAlibabaConfig = JSON.parse(JSON.stringify(AlibabaConfig));

                let endpoint = (regionEndpointMap[serviceLower] && regionEndpointMap[serviceLower].includes(region)) ?
                    `https://${serviceLower}.${region}.aliyuncs.com` : `https://${serviceLower}.aliyuncs.com`;
                LocalAlibabaConfig['endpoint'] = endpoint;
                LocalAlibabaConfig['apiVersion'] = callObj.apiVersion;
                let client = new alicloud(LocalAlibabaConfig);
                let paginating = false;
                let pageNumber = 1;
                var clientCb = function(err, data) {
                    if (err) collection[serviceLower][callKey][region].err = err;
                    if (!data) return regionCb();
                    if (callObj.property && !data[callObj.property]) return regionCb();
                    if (callObj.subProperty && !data[callObj.property][callObj.subProperty]) return regionCb();

                    var dataToAdd = callObj.subProperty ? data[callObj.property][callObj.subProperty] : data[callObj.property];

                    if (paginating) {
                        collection[serviceLower][callKey][region].data = collection[serviceLower][callKey][region].data.concat(dataToAdd);
                    } else {
                        collection[serviceLower][callKey][region].data = dataToAdd;
                    }

                    if (callObj.paginate && callObj.paginate == 'Pages' && settings.paginate) {
                        if (data['PageNumber'] && data['PageSize'] && data['TotalCount']) {
                            let pageSize = callObj.pageSize || parseInt(data['PageSize']);
                            let totalCount = parseInt(data['TotalCount']);

                            if ((pageNumber*pageSize) < totalCount) {
                                paginating = true;
                                pageNumber += 1;
                                let paginateParams = { PageNumber: pageNumber, PageSize: pageSize};
                                return execute(null, paginateParams);
                            }
                        }
                    }

                    var nextToken = callObj.paginate;
                    if (settings.paginate && nextToken && data[nextToken]) {
                        paginating = true;
                        var paginateProp = callObj.paginateReqProp ? callObj.paginateReqProp : nextToken;
                        return execute([paginateProp, data[nextToken]]);
                    }

                    if (callObj.rateLimit) {
                        setTimeout(function() {
                            regionCb();
                        }, callObj.rateLimit);
                    } else {
                        regionCb();
                    }
                };

                function execute(nextToken, paginateParams) {
                    let localParams = JSON.parse(JSON.stringify(callObj.params || {}));
                    localParams['RegionId'] = region;
                    if (nextToken) localParams[nextToken[0]] = nextToken[1];
                    else if (paginateParams) localParams = {...localParams, ...paginateParams};

                    client.request(callKey, localParams, requestOption).then((result) => {
                        clientCb(null, result);
                    }, (err) => {
                        clientCb(err);
                    });
                }

                execute();
            }, function() {
                callCb();
            });
        }, function() {
            serviceCb();
        });
    }, function() {
        async.eachSeries(postcalls, function(postcallObj, postcallCb) {
            async.eachOfLimit(postcallObj, 10, function(serviceObj, service, serviceCb) {
                var serviceLower = service.toLowerCase();
                if (!collection[serviceLower]) collection[serviceLower] = {};

                async.eachOfLimit(serviceObj, 1, function(callObj, callKey, callCb) {
                    if (settings.api_calls && settings.api_calls.indexOf(service + ':' + callKey) === -1) return callCb();
                    if (!collection[serviceLower][callKey]) collection[serviceLower][callKey] = {};

                    var requestOption = { method: callObj.method || 'POST' };
                    async.eachLimit(regions[serviceLower], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                        if (settings.skip_regions &&
                            settings.skip_regions.indexOf(region) > -1 &&
                            globalServices.indexOf(service) === -1) return regionCb();
                        if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                        if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return regionCb();

                        if (callObj.reliesOnCall &&
                            (!collection[callObj.reliesOnService] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region] ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data ||
                            !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data.length))
                            return regionCb();

                        let LocalAlibabaConfig = JSON.parse(JSON.stringify(AlibabaConfig));

                        LocalAlibabaConfig['endpoint'] = (regionEndpointMap[serviceLower] && regionEndpointMap[serviceLower].includes(region)) ?
                            `https://${serviceLower}.${region}.aliyuncs.com` : `https://${serviceLower}.aliyuncs.com`;
                        LocalAlibabaConfig['apiVersion'] = callObj.apiVersion;
                        let client = new alicloud(LocalAlibabaConfig);

                        async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall][region].data, 10, function(val, valCb) {
                            let resultKey = callObj.filterValue[0];
                            collection[serviceLower][callKey][region][val[resultKey]] = {};

                            let params = {};
                            if (callObj.params) params = JSON.parse(JSON.stringify(callObj.params));

                            for (let key in callObj.filterKey) {
                                params[callObj.filterKey[key]] = val[callObj.filterValue[key]];
                            }

                            params['RegionId'] = region;

                            var requestCb = function(err, data) {
                                if (err) collection[serviceLower][callKey][region][val[resultKey]].err = err;
                                if (!data) return valCb();

                                collection[serviceLower][callKey][region][val[resultKey]].data = (callObj.resultFilter && data[callObj.resultFilter]) ?
                                    data[callObj.resultFilter] : data;

                                if (callObj.rateLimit) {
                                    setTimeout(function() {
                                        valCb();
                                    }, callObj.rateLimit);
                                } else {
                                    valCb();
                                }
                            };

                            var execute = function() {  
                                client.request(callKey, params, requestOption).then((result) => {
                                    requestCb(null, result);
                                }, (err) => {
                                    requestCb(err);
                                });
                            };

                            execute();
                        }, function() {
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
            }, function() {
                postcallCb();
            });
        }, function() {
            callback(null, collection);
        });
    });
};

module.exports = collect;
