/*********************
 Collector - The collector will query Google APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - GoogleConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["us-east2", "eu-west1"],
     "api_calls": ["", ""]
 }
 - callback: Function to call when the collection is complete
 *********************/
var async = require('async');

var helpers = require(__dirname + '/../../helpers/google');

var calls = {
    disks: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'zone'
        }
    },
    securityPolicies: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    firewalls: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    instances: {
        compute: { 
            list: {
                api: 'compute',
                version: 'v1',
                location: 'zone'
            },
            aggregatedList: {
                api: 'compute',
                version: 'v1',
                location: null
            }
        },
        sql: {
            list: {
                api: 'sqladmin',
                version: 'v1beta4',
                location: null
            }
        },
        manyApi: true,
    },
    instanceGroups: {
        aggregatedList: {
            api: 'compute',
            version: 'v1',
            location: null,
        }
    },
    keyRings: {
        list: {
            api: 'cloudkms',
            version: 'v1',
            location: 'region',
            parent: true,
            nested: true,
        }
    },
    networks: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    backendServices: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    healthChecks: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    buckets: {
        list: {
            api: 'storage',
            version: 'v1',
            location: null,
        }
    },
    targetHttpProxies: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'global'
        }
    },
    autoscalers: {
        aggregatedList: {
            api: 'compute',
            version: 'v1',
            location: 'null'
        }
    },
    subnetworks: {
        list: {
            api: 'compute',
            version: 'v1',
            location: 'region',
        }
    },
    projects: {
        get: {
            api: 'compute',
            version: 'v1',
            location: null
        },
        getIamPolicy: {
            api: 'cloudresourcemanager',
            version: 'v1',
            resource: true
        }
    },
    clusters: {
        list: {
            api: 'container',
            version: 'v1beta1',
            location: 'global',
            parent: true,
            nested: true,
        }
    },
    managedZones: {
        list: {
            api: 'dns',
            version: 'v1',
            location: null
        }
    },
    metrics: {
        list: {
            api: 'logging',
            version: 'v2',
            parent: true
        }
    },
    alertPolicies: {
        list: {
            api: 'monitoring',
            version: 'v3',
            parent: 'name'
        }
    },
    serviceAccounts: {
        list: {
            api: 'iam',
            version: 'v1',
            parent: 'name'
        }
    },
    sinks: {
        list: {
            api: 'logging',
            version: 'v2',
            parent: true
        }
    },
};

var postcalls = {
    instances: {
        getIamPolicy: {
            api: 'compute',
            version: 'v1',
            location: 'zone',
            reliesOnService: ['instances'],
            reliesOnCall: ['list'],
            filterKey: ['resource_'],
            filterValue: ['id'],
        }
    },
    cryptoKeys: {
        list: {
            api: 'cloudkms',
            version: 'v1',
            location: 'region',
            reliesOnService: ['keyRings'],
            reliesOnCall: ['list'],
            filterKey: ['parent'],
            filterValue: ['name'],
            nested: true
        }
    },
    buckets: {
        getIamPolicy: {
            api: 'storage',
            version: 'v1',
            location: null,
            reliesOnService: ['buckets'],
            reliesOnCall: ['list'],
            filterKey: ['bucket'],
            filterValue: ['name'],
        }
    },
    keys: {
        list: {
            api: 'iam',
            version: 'v1',
            parent: 'name',
            serviceAccount: true,
            reliesOnService: ['serviceAccounts'],
            reliesOnCall: ['list'],
            filterKey: ['id'],
            filterValue: ['uniqueId']
        }
    },
    users: {
        list: {
            api: 'sqladmin',
            version: 'v1beta4',
            location: null,
            reliesOnService: ['instances'],
            reliesOnSubService: ['sql'],
            reliesOnCall: ['list'],
            filterKey: ['instance'],
            filterValue: ['name'],
        }
    }


};

var collect = function(GoogleConfig, settings, callback) {
    var collection = {};

    GoogleConfig.maxRetries = 5;
    GoogleConfig.retryDelayOptions = {base: 300};

    var regions = helpers.regions();

    helpers.authenticate(GoogleConfig)
        .then(client => {
            
            async.eachOfLimit(calls, 10, function(call, service, serviceCb) {
                if (!collection[service]) collection[service] = {};

                helpers.processCall(GoogleConfig, collection, settings, regions, call, service, client, function() {
                    serviceCb();
                });
            }, function() {
                async.eachOfLimit(postcalls, 10, function(postcallObj, service, postcallCb) {
                    helpers.processCall(GoogleConfig, collection, settings, regions, postcallObj, service, client, function() {
                        postcallCb();
                    });
                }, function() {
                    callback(null, collection);
                });
            });
        });
};

module.exports = collect;