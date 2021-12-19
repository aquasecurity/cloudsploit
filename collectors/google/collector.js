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
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectid}/zones/{locationId}/disks',
            location: 'zone',
            pagination: true
        },
        aggregatedList: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/disks',
            location: null,
            pagination: true
        }
    },
    images: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectid}/global/images',
            location: null,
            pagination: true
        }
    },
    snapshots: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/snapshots',
            location: null,
            pagination: true
        }
    },
    securityPolicies: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/securityPolicies',
            location: null,
            pagination: true
        }
    },
    resourcePolicies: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/regions/{locationId}/resourcePolicies',
            location: 'region',
            pagination: true
        }
    },
    firewalls: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/firewalls',
            location: null,
            pagination: true
        }
    },
    instances: {
        compute: { 
            list: {
                url: `https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instances`,
                location: 'zone',
                pagination: true
            },
            aggregatedList: {
                url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/instances',
                location: null,
                pagination: true
            }
        },
        sql: {
            list: {
                url: 'https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances',
                location: null,
                pagination: true
            }
        },
        spanner: {
            list: {
                url: 'https://spanner.googleapis.com/v1/projects/{projectId}/instances',
                location: null,
                pagination: true
            }
        },
        manyApi: true,
    },
    instanceTemplates: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/instanceTemplates',
            location: null,
            pagination: true
        }
    },
    instanceGroups: {
        aggregatedList: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/instanceGroups',
            location: null,
            pagination: true
        }
    },
    functions: {
        list : {
            url: 'https://cloudfunctions.googleapis.com/v1/projects/{projectId}/locations/{locationId}/functions',
            location: 'region',
            paginationKey: 'pageSize',
            pagination: true
        }
    },
    keyRings: {
        list: {
            url: 'https://cloudkms.googleapis.com/v1/projects/{projectId}/locations/{locationId}/keyRings',
            location: 'region',
            paginationKey: 'pageSize',
            pagination: true
        }
    },
    networks: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/networks',
            location: null,
            pagination: true
        }
    },
    backendServices: {
        list: {
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/global/backendServices',
            location: null,
            pagination: true
        }
    },
    healthChecks: {
        list: {
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/global/healthChecks',
            location: null,
            pagination: true
        }
    },
    buckets: {
        list: {
            url: 'https://storage.googleapis.com/storage/v1/b?project={projectId}',
            location: null,
            pagination: true
        }
    },
    targetHttpProxies: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/targetHttpProxies',
            location: null,
            pagination: true
        }
    },
    autoscalers: {
        aggregatedList: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/autoscalers',
            location: null,
            pagination: true
        }
    },
    subnetworks: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/regions/{locationId}/subnetworks',
            location: 'region',
            pagination: true
        }
    },
    projects: {
        get: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}',
            pagination: false
        },
        getIamPolicy: {
            url: 'https://cloudresourcemanager.googleapis.com/v1/projects/{projectId}:getIamPolicy',
            location: null,
            method: 'POST',
            pagination: false
        }
    },
    clusters: {
        list: {
            url: 'https://container.googleapis.com/v1/projects/{projectId}/locations/-/clusters',
            location: null,
            pagination: false
        }
    },
    managedZones: {
        list: {
            url: 'https://dns.googleapis.com/dns/v1/projects/{projectId}/managedZones',
            location: null,
            pagination: true
        }
    },
    metrics: {
        list: {
            url: 'https://logging.googleapis.com/v2/projects/{projectId}/metrics',
            location: null,
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    alertPolicies: {
        list: {
            url: 'https://monitoring.googleapis.com/v3/projects/{projectId}/alertPolicies',
            location: null,
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    serviceAccounts: {
        list: {
            url: 'https://iam.googleapis.com/v1/projects/{projectId}/serviceAccounts',
            location: null,
            pagination: true,
            paginationKey: 'pageSize'
            
        }
    },
    sinks: {
        list: {
            url: 'https://logging.googleapis.com/v2/projects/{projectId}/sinks',
            location: null,
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    datasets: {
        list: {
            url: 'https://bigquery.googleapis.com/bigquery/v2/projects/{projectId}/datasets',
            location: null,
            pagination: true
        }
    },
    policies: {
        list: {
            url: 'https://dns.googleapis.com/dns/v1/projects/{projectId}/policies',
            location: null,
            pagination: true
        }
    },
    topics: {
        list: {
            url: 'https://pubsub.googleapis.com/v1/projects/{projectId}/topics',
            location: null, 
            pagination: true,
            paginationKey: 'pageSize'
            
        }
    },
    subscriptions: {
        list: {
            url: 'https://pubsub.googleapis.com/v1/projects/{projectId}/subscriptions',
            location: null, 
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    jobs: {
        list: { //https://dataflow.googleapis.com/v1b3/projects/{projectId}/jobs:list
            url: 'https://dataflow.googleapis.com/v1b3/projects/{projectId}/locations/{locationId}/jobs',
            location: 'region', 
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    deployments: { // https://www.googleapis.com/deploymentmanager/v2/projects/project/global/deployments
        list: {
            url: 'https://www.googleapis.com/deploymentmanager/v2/projects/{projectId}/global/deployments',
            location: null, 
            pagination: true,            
        }
    },
    organizations:{ // https://cloudresourcemanager.googleapis.com/v1beta1/organizations
        list: {
            url: 'https://cloudresourcemanager.googleapis.com/v1beta1/organizations',
            pagination: false
        },
    },
    urlMaps: { // https://compute.googleapis.com/compute/v1/projects/{project}/global/urlMaps
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/urlMaps',
            location: null,
            pagination: true
        }
    }
};

var postcalls = {
    instances: {
        getIamPolicy: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instances/{id}/getIamPolicy',
            location: 'zone',
            reliesOnService: ['instances'],
            reliesOnCall: ['list'],
            properties: ['id'],
            pagination: false
        }
    },
    cryptoKeys: {
        list: {
            url: 'https://cloudkms.googleapis.com/v1/{name}/cryptoKeys',
            location: 'region',
            reliesOnService: ['keyRings'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    buckets: {
        getIamPolicy: {
            url: 'https://storage.googleapis.com/storage/v1/b/{name}/iam',
            location: null,
            reliesOnService: ['buckets'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        }
    },
    keys: {
        list: {
            url: 'https://iam.googleapis.com/v1/{name}/keys',
            reliesOnService: ['serviceAccounts'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false        
        }
    },
    users: {
        list: {
            url: 'https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances/{name}/users',
            location: null,
            reliesOnService: ['instances'],
            reliesOnSubService: ['sql'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true //needs to be verified with multiple users
        }
    },
    backupRuns: {
        list: {
            url: 'https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances/{name}/backupRuns',
            location: null,
            reliesOnService: ['instances'],
            reliesOnSubService: ['sql'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true
        }
    },
    datasets: {
        get: {
            url: 'https://bigquery.googleapis.com/bigquery/v2/projects/{projectId}/datasets/{datasetId}',
            location: null,
            reliesOnService: ['datasets'],
            reliesOnCall: ['list'],
            properties: ['datasetId'],
            subObj: ['datasetReference'],
            pagination: true
        }
    },
    jobs: {
        get: { //https://dataflow.googleapis.com/v1b3/projects/{projectId}/jobs/{jobId}
            url: 'https://dataflow.googleapis.com/v1b3/projects/{projectId}/locations/{locationId}/jobs/{id}',
            reliesOnService: ['jobs'],
            reliesOnCall: ['list'],
            location: 'region',
            properties: ['id'],
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    organizations: { //https://cloudresourcemanager.googleapis.com/v1beta1/{resource=organizations/*}:getIamPolicy
        getIamPolicy: {
            url:'https://cloudresourcemanager.googleapis.com/v1/organizations/{organizationId}:getIamPolicy',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId'],
            method: 'POST', 
            pagination: false
        },
        listOrgPolicies: {
            url: 'https://cloudresourcemanager.googleapis.com/v1/organizations/{organizationId}:listOrgPolicies',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId'],
            method: 'POST', 
            pagination: true,
            paginationKey: 'pageSize'
        }
    }
};

var collect = function(GoogleConfig, settings, callback) {
    var collection = {};

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