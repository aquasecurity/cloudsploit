/*
 enabled: send integration is enable or not
 isSingleSource: whether resource is single source or not

----------Bridge Side Data----------
 BridgeServiceName: it should be the api service name which we are storing in json file in s3 collection bucket.
 BridgeCall: it should be the api call which we are storing in json file in s3 collection bucket.
 BridgePluginCategoryName: it should be equivalent to Plugin Category Name.
 BridgeProvider: it should be the cloud provider
                 Eg. 'aws', 'Azure', 'Google'

 BridgeArnIdentifier: no need to pass.

 BridgeIdTemplate: this should be the template for creating the resource id.
                    supported values: name, region, cloudAccount, project, id
                    Eg. 'projects/{cloudAccount}/regions/{region}/clusters/{name}'


 BridgeResourceType: this should be type of the resource, fetch it from the id.
                     Eg. 'servers'

 BridgeResourceNameIdentifier: it should be the key of resource name/id data which we are storing in json file in  s3 collection bucket.
                               Eg. 'Name/name' or 'Id/id'.

 Note: if there is no name then we have to pass the id.

 BridgeExecutionService: it should be equivalent to service name which we are sending from executor in payload data.
 BridgeCollectionService: it should be equivalent to service name which we are sending from collector in payload data.
 DataIdentifier: it should be the parent key field of data which we want to collect in json file in s3 collection bucket.

----------Processor Side Data----------
These fields should be according to the user and product manager, what they want to show in Inventory UI.
 InvAsset: 'Pub/Sub'
 InvService: 'Pub/Sub'
 InvResourceCategory: 'cloud_resources'
    Note: For specific category add the category name otherwise it should be 'cloud_resource'

 InvResourceType: 'Pub/Sub'
    If you need that your resource type to be two words with capital letter only on first letter of the word (for example: Key Vaults), you should supply the resource type with a space delimiter.
    If you need that your resource type to be two words and the the first word should be in capital letters (for example: CDN Profiles), you should supply the resource type with snake case delimiter


 Take the reference from the below map
*/

// Note: In Below service map add only single source resources.
// and service name should be plugin category.

var serviceMap = {
    'Pub/Sub':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Pub/Sub', InvService: 'Pub/Sub',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Pub/Sub', BridgeServiceName: 'topics',
            BridgePluginCategoryName: 'gcp-Pub/Sub', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'topics',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Pub/Sub',
            BridgeCollectionService: 'gcp-topics', DataIdentifier: 'data',
        },
    'DNS':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Managed Zone', InvService: 'DNS',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'DNS', BridgeServiceName: 'managedzones',
            BridgePluginCategoryName: 'gcp-DNS', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'projects/{cloudAccount}/zones/{name}',
            BridgeResourceType: 'zones', BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-DNS',
            BridgeCollectionService: 'gcp-managedZones', DataIdentifier: 'data',
        },
    'VPC Network':
        {
            enabled: true, isSingleSource: true, InvAsset: 'VPC Network', InvService: 'VPC Network',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'VPC Network', BridgeServiceName: 'networks',
            BridgePluginCategoryName: 'gcp-VPC Network', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'networks',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-VPC Network',
            BridgeCollectionService: 'gcp-networks', DataIdentifier: 'data',
        },
    'Cryptographic Keys':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Cryptographic Key', InvService: 'Cryptographic Keys',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Cryptographic Key', BridgeServiceName: 'cryptokeys',
            BridgePluginCategoryName: 'gcp-Cryptographic Keys', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'cryptoKeys',
            BridgeResourceNameIdentifier: '', BridgeExecutionService: 'gcp-Cryptographic Keys',
            BridgeCollectionService: 'gcp-cryptoKeys', DataIdentifier: 'data',
        },
    'CLB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Url Map', InvService: 'CLB',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'CLB', BridgeServiceName: 'urlmaps',
            BridgePluginCategoryName: 'gcp-CLB', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'urlMaps',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-CLB',
            BridgeCollectionService: 'gcp-urlMaps', DataIdentifier: 'data',
        },
    'Deployment Manager':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Deployment', InvService: 'Deployment Manager',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Deployment Manager', BridgeServiceName: 'deployments',
            BridgePluginCategoryName: 'gcp-Deployment Manager', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'deployments',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Deployment Manager',
            BridgeCollectionService: 'gcp-deployments', DataIdentifier: 'data',
        },
    'Logging':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Alert Policy', InvService: 'Logging',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Logging', BridgeServiceName: 'alertpolicies',
            BridgePluginCategoryName: 'gcp-Logging', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'alertPolicies',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Logging',
            BridgeCollectionService: 'gcp-alertPolicies', DataIdentifier: 'data',
        },
    'Dataproc':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Cluster', InvService: 'Dataproc',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Dataproc', BridgeServiceName: 'dataproc',
            BridgePluginCategoryName: 'gcp-Dataproc', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'projects/{cloudAccount}/regions/{region}/clusters/{name}',
            BridgeResourceType: 'clusters', BridgeResourceNameIdentifier: 'clusterName', BridgeExecutionService: 'gcp-Dataproc',
            BridgeCollectionService: 'gcp-dataproc', DataIdentifier: 'data',
        },
    'Dataflow':
        {
            enabled: true, isSingleSource: true, InvAsset: 'job', InvService: 'Dataflow',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Dataflow Job', BridgeServiceName: 'jobs',
            BridgePluginCategoryName: 'gcp-Dataflow', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'projects/{cloudAccount}/jobs/{id}', BridgeResourceType: 'jobs',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Dataflow',
            BridgeCollectionService: 'gcp-jobs', DataIdentifier: 'data',
        },
    'API':
        {
            enabled: true, isSingleSource: true, InvAsset: 'API', InvService: 'API',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'API', BridgeServiceName: 'apikeys',
            BridgePluginCategoryName: 'gcp-API', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'keys',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-API',
            BridgeCollectionService: 'gcp-apiKeys', DataIdentifier: 'data',
        },
    'BigQuery':
        {
            enabled: true, isSingleSource: true, InvAsset: 'dataset', InvService: 'BigQuery',
            InvResourceCategory: 'database', InvResourceType: 'BigQuery', BridgeServiceName: 'datasets',
            BridgePluginCategoryName: 'gcp-BigQuery', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'projects/{cloudAccount}/datasets/{name}', BridgeResourceType: 'datasets',
            BridgeResourceNameIdentifier: 'datasetId', BridgeExecutionService: 'gcp-BigQuery',
            BridgeCollectionService: 'gcp-datasets', DataIdentifier: 'data',
        },
    'BigTable':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Instance', InvService: 'BigTable',
            InvResourceCategory: 'database', InvResourceType: 'BigTable', BridgeServiceName: 'bigtable',
            BridgePluginCategoryName: 'gcp-BigTable', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'instances',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-BigTable',
            BridgeCollectionService: 'gcp-bigtable', DataIdentifier: 'data',
        },
    'Spanner':
        {
            enabled: true, isSingleSource: true, InvAsset: 'Instance', InvService: 'Spanner',
            InvResourceCategory: 'database', InvResourceType: 'Spanner', BridgeServiceName: 'spanner',
            BridgePluginCategoryName: 'gcp-Spanner', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'instances',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Spanner',
            BridgeCollectionService: 'gcp-spanner', DataIdentifier: 'data',
        },
    'SQL':
        {
            enabled: true, isSingleSource: true, InvAsset: 'sql', InvService: 'sql',
            InvResourceCategory: 'database', InvResourceType: 'sql', BridgeServiceName: 'sql',
            BridgePluginCategoryName: 'gcp-SQL', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'instances',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-SQL',
            BridgeCollectionService: 'gcp-sql', DataIdentifier: 'data',
        },
    'Storage':
        {
            enabled: true, isSingleSource: true, InvAsset: 'storage', InvService: 'storage',
            InvResourceCategory: 'storage', InvResourceType: 'bucket', BridgeServiceName: 'buckets',
            BridgePluginCategoryName: 'gcp-Storage', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'b',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Storage',
            BridgeCollectionService: 'gcp-buckets', DataIdentifier: 'data',
        },
    'AI & ML':
        {
            enabled: true, isSingleSource: true, InvAsset: 'models', InvService: 'vertexAI',
            InvResourceCategory: 'ai&ml', InvResourceType: 'VertexAI models', BridgeServiceName: 'vertexAI',
            BridgePluginCategoryName: 'gcp-AI & ML', BridgeProvider: 'Google', BridgeCall: 'listModels',
            BridgeArnIdentifier: '', BridgeIdTemplate: '{name}', BridgeResourceType: 'models',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-AI & ML',
            BridgeCollectionService: 'gcp-vertexai', DataIdentifier: 'data',
        },
    'CloudBuild':
        {
            enabled: true, isSingleSource: true, InvAsset: 'trigger', InvService: 'CloudBuild',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'trigger', BridgeServiceName: 'cloudbuild',
            BridgePluginCategoryName: 'gcp-CloudBuild', BridgeProvider: 'Google', BridgeCall: 'triggers',
            BridgeArnIdentifier: '', BridgeIdTemplate: 'projects/{cloudAccount}/locations/{region}/triggers/{name}', BridgeResourceType: 'triggers',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-CloudBuild',
            BridgeCollectionService: 'gcp-cloudbuild', DataIdentifier: 'data',
        },
    'Cloud Composer':
        {
            enabled: true, isSingleSource: true, InvAsset: 'environment', InvService: 'Cloud Composer',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'composer_environment', BridgeServiceName: 'composer',
            BridgePluginCategoryName: 'gcp-Cloud Composer', BridgeProvider: 'Google', BridgeCall: 'environments',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'environments',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Cloud Composer',
            BridgeCollectionService: 'gcp-composer', DataIdentifier: 'data',
        },
    'Resource Manager':
        {
            enabled: true, isSingleSource: true, InvAsset: 'organization', InvService: 'Resource Manager',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Organization', BridgeServiceName: 'organizations',
            BridgePluginCategoryName: 'gcp-Resource Manager', BridgeProvider: 'Google', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'organizations',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'gcp-Resource Manager',
            BridgeCollectionService: 'gcp-organizations', DataIdentifier: 'data',
        }
};
var calls = {
    disks: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/disks',
            location: 'zone',
            pagination: true
        },
        aggregatedList: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/disks',
            location: null,
            pagination: true
        }
    },
    composer: {
        environments: {
            url: 'https://composer.googleapis.com/v1/projects/{projectId}/locations/{locationId}/environments',
            location: 'region',
            pagination: true,
            paginationKey: 'pageToken',
            dataFilterKey: 'environments'
        },
        sendIntegration: serviceMap['Cloud Composer']
    },
    repositories: {
        list: {
            url: 'https://artifactregistry.googleapis.com/v1/projects/{projectId}/locations/{locationId}/repositories',
            location: 'region',
            pagination: true
        },
        sendIntegration: {
            enabled: true
        }
    },
    apiGateways: {
        list: {
            url: 'https://apigateway.googleapis.com/v1/projects/{projectId}/locations/{locationId}/gateways',
            location: 'region',
            dataKey: 'gateways',
            isDataArray: true
        }
    },
    api: {
        list: {
            url: 'https://apigateway.googleapis.com/v1/projects/{projectId}/locations/{locationId}/apis',
            location: 'region',
            dataKey: 'apis',
            isDataArray: true
        }
    },
    images: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/images',
            location: null,
            pagination: true,
            ignoreMiscData: true
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
    compute: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instances',
            location: 'zone',
            ignoreMiscData: true,
            pagination: true
        },
        aggregatedList: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/aggregated/instances',
            location: null,
            pagination: true
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['resourceRecordSets', 'firewalls', 'projects']
            }
        },
    },
    sql: {
        list: {
            url: 'https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances',
            location: null,
            pagination: true
        },
        sendIntegration: serviceMap['SQL']
    },
    spanner: {
        list: {
            url: 'https://spanner.googleapis.com/v1/projects/{projectId}/instances',
            location: null,
            pagination: true,
            paginationKey: 'pageSize',
            dataFilterKey: 'instances'
        },
        sendIntegration: serviceMap['Spanner']
    },
    bigtable: {
        list: {
            url: 'https://bigtableadmin.googleapis.com/v2/projects/{projectId}/instances',
            location: null,
            pagination: true,
            paginationKey: 'pageToken',
            dataFilterKey: 'instances'
        },
        sendIntegration: serviceMap['BigTable']
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
        },
        list : {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instanceGroups',
            location: 'zone',
            pagination: true,
            ignoreMiscData: true

        }
    },
    instanceGroupManagers: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instanceGroupManagers',
            location: 'zone',
            pagination: true
        }
    },
    functions: {
        list : {
            url: 'https://cloudfunctions.googleapis.com/v1/projects/{projectId}/locations/{locationId}/functions',
            location: 'region',
            paginationKey: 'pageSize',
            pagination: true
        },
        sendIntegration: {
            enabled: true
        }
    },
    functionsv2: {
        list : {
            url: 'https://run.googleapis.com/v2/projects/{projectId}/locations/{locationId}/services',
            location: 'region',
            paginationKey: 'pageSize',
            pagination: true,
            dataFilterKey: 'services'
        },
        sendIntegration: {
            enabled: true
        }
    },
    keyRings: {
        list: {
            url: 'https://cloudkms.googleapis.com/v1/projects/{projectId}/locations/{locationId}/keyRings',
            location: 'region',
            paginationKey: 'pageSize',
            pagination: true
        },
    },
    networks: {
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/networks',
            location: null,
            pagination: true
        },
        sendIntegration: serviceMap['VPC Network']
    },
    backendServices: {
        list: {
            globalURL: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/global/backendServices',
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/regions/{locationId}/backendServices',
            location: 'region',
            pagination: true,
            ignoreMiscData: true
        },
    },

    forwardingRules: {
        list: {
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/regions/{locationId}/forwardingRules',
            globalURL: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/global/forwardingRules',
            location: 'region',
            pagination: true,
            ignoreMiscData: true
        },
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
        },
        sendIntegration: serviceMap['Storage']
    },
    targetHttpProxies: {
        list: {
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/regions/{locationId}/targetHttpProxies',
            globalURL: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/targetHttpProxies',
            location: 'region',
            pagination: true,
            ignoreMiscData: true,
        }
    },
    targetHttpsProxies: {
        list: {
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/regions/{locationId}/targetHttpsProxies',
            globalURL: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/targetHttpsProxies',
            location: 'region',
            pagination: true,
            ignoreMiscData: true
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
        list:{
            url: 'https://cloudresourcemanager.googleapis.com/v1/projects',
            pagination: true,
        },
        get: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}',
            pagination: false
        },
        getIamPolicy: {
            url: 'https://cloudresourcemanager.googleapis.com/v3/projects/{projectId}:getIamPolicy',
            location: null,
            method: 'POST',
            pagination: false,
            body: {options:{requestedPolicyVersion: 3}}
        },
        getWithNumber: {
            url: 'https://cloudresourcemanager.googleapis.com/v1/projects/{projectId}'
        }
    },
    kubernetes: {
        list: {
            url: 'https://container.googleapis.com/v1/projects/{projectId}/locations/-/clusters',
            location: null,
            pagination: false
        },
        sendIntegration: {
            enabled: true
        }
    },
    dataproc: {
        list: {
            url: 'https://dataproc.googleapis.com/v1/projects/{projectId}/regions/{locationId}/clusters',
            location: 'region',
            pagination: true
        },
        sendIntegration: serviceMap['Dataproc']
    },
    cloudbuild: {
        triggers: {
            url: 'https://cloudbuild.clients6.google.com/v1/projects/{projectId}/locations/{locationId}/triggers',
            location: 'region',
            dataFilterKey: 'triggers'
        },
        sendIntegration: serviceMap['CloudBuild']
    },
    managedZones: {
        list: {
            url: 'https://dns.googleapis.com/dns/v1/projects/{projectId}/managedZones',
            location: null,
            pagination: true
        },
        sendIntegration: serviceMap['DNS']
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
        },
        sendIntegration: serviceMap['Logging']
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
            pagination: true,
            reqParams: 'maxResults=1000'
        },
        sendIntegration: serviceMap['BigQuery']
    },
    policies: {
        list: {
            url: 'https://dns.googleapis.com/dns/v1/projects/{projectId}/policies',
            location: null,
            pagination: true
        },
        projectDenyPolicies: { //GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Fprojects%252Fprojectid/denypolicies
            url: 'https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Fprojects%252F{projectId}/denypolicies',
            pagination: true
        },
    },
    topics: {
        list: {
            url: 'https://pubsub.googleapis.com/v1/projects/{projectId}/topics',
            location: null,
            pagination: true,
            paginationKey: 'pageSize'
        },
        sendIntegration: serviceMap['Pub/Sub']
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
        },
        sendIntegration: serviceMap['Dataflow']
    },
    deployments: { // https://www.googleapis.com/deploymentmanager/v2/projects/project/global/deployments
        list: {
            url: 'https://www.googleapis.com/deploymentmanager/v2/projects/{projectId}/global/deployments',
            location: null,
            pagination: true,
        },
        sendIntegration: serviceMap['Deployment Manager']
    },
    organizations:{ // https://cloudresourcemanager.googleapis.com/v1beta1/organizations
        list: {
            url: 'https://cloudresourcemanager.googleapis.com/v1beta1/organizations',
            pagination: false
        }
    },
    urlMaps: { // https://compute.googleapis.com/compute/v1/projects/{projectid}/global/urlMaps
        list: {
            globalURL: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/urlMaps',
            url: 'https://compute.googleapis.com/compute/beta/projects/{projectId}/regions/{locationId}/urlMaps',
            location: 'region',
            pagination: true,
            nameRequired: true,
            ignoreMiscData: true
        },
        sendIntegration: serviceMap['CLB']
    },
    apiKeys: {
        list: {
            url: 'https://apikeys.googleapis.com/v2/projects/{projectId}/locations/global/keys',
            location: null
        },
        sendIntegration: serviceMap['API']
    },
    resourceRecordSets: {
        list: {
            url: 'https://dns.googleapis.com/dns/v1/projects/{projectId}/managedZones/{id}/rrsets',
            reliesOnService: ['managedZones'],
            reliesOnCall: ['list'],
            properties: ['id'],
            pagination: true
        }
    },
    accessApproval: {
        settings: {
            url: 'https://accessapproval.googleapis.com/v1/projects/{projectId}/accessApprovalSettings',
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    networkRoutes:{
        list: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/routes',
            location: null,
            pagination: true
        }
    },
    vertexAI: {
        listDatasets: {
            url: 'https://{locationId}-aiplatform.googleapis.com/v1/projects/{projectId}/locations/{locationId}/datasets',
            location: 'region',
            dataKey: 'datasets',
            isDataArray: true
        },
        listModels: {
            url: 'https://{locationId}-aiplatform.googleapis.com/v1/projects/{projectId}/locations/{locationId}/models',
            location: 'region',
            dataKey: 'models'
        },
        sendIntegration: serviceMap['AI & ML']
    },

    roles: {
        list: {
            url: 'https://iam.googleapis.com/v1/projects/{projectId}/roles',
            location: null,
            pagination: true,
            paginationKey: 'nextPageToken'
        },
        predefined_list: {
            url: 'https://iam.googleapis.com/v1/roles',
            location: null,
            pagination: true,
            paginationKey: 'nextPageToken'
        }
    },
};

var postcalls = {
    roles: {
        get: {
            url: 'https://iam.googleapis.com/v1/{name}',
            location: null,
            reliesOnService: ['roles'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        },
        predefined_get: {
            url: 'https://iam.googleapis.com/v1/{name}',
            location: null,
            reliesOnService: ['roles'],
            reliesOnCall: ['predefined_list'],
            properties: ['name'],
            pagination: false
        },

    },
    compute: {
        getIamPolicy: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/{locationId}/instances/{id}/getIamPolicy',
            location: 'zone',
            reliesOnService: ['compute'],
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
        },
        sendIntegration: serviceMap['Cryptographic Keys']
    },
    buckets: {
        getIamPolicy: {
            url: 'https://storage.googleapis.com/storage/v1/b/{name}/iam',
            location: null,
            reliesOnService: ['buckets'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        },
        sendIntegration: {
            integrationReliesOn: {
                serviceName: ['buckets']
            }
        },
    },
    topics: {
        getIamPolicy: {
            url: 'https://pubsub.googleapis.com/v1/{name}:getIamPolicy',
            location: null,
            reliesOnService: ['topics'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        },
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
            reliesOnService: ['sql'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true //needs to be verified with multiple users
        },
        sendIntegration: {
            integrationReliesOn: {
                serviceName: ['sql']
            }
        },
    },
    backupRuns: {
        list: {
            url: 'https://sqladmin.googleapis.com/sql/v1beta4/projects/{projectId}/instances/{name}/backupRuns',
            location: null,
            reliesOnService: ['sql'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true
        },
        sendIntegration: {
            integrationReliesOn: {
                serviceName: ['sql']
            }
        },
    },
    apiConfigs: {
        list: {
            url: 'https://apigateway.googleapis.com/v1/{name}/configs',
            location: 'region',
            reliesOnService: ['api'],
            reliesOnCall: ['list'],
            properties: ['name'],
        }
    },
    apiGateways: {
        getIamPolicy: {
            url: 'https://apigateway.googleapis.com/v1/{name}:getIamPolicy',
            location: 'region',
            reliesOnService: ['apiGateways'],
            reliesOnCall: ['list'],
            properties: ['name'],
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
    bigqueryTables: {
        list: {
            url: 'https://bigquery.googleapis.com/bigquery/v2/projects/{projectId}/datasets/{datasetId}/tables',
            location: null,
            reliesOnService: ['datasets'],
            reliesOnCall: ['list'],
            properties: ['datasetId'],
            subObj: ['datasetReference'],
            pagination: true,
            dataKey: 'tables',
            reqParams: 'maxResults=1000',
            maxLimit: 50000
        }
    },
    functions: {
        getIamPolicy : {
            url: 'https://cloudfunctions.googleapis.com/v1/{name}:getIamPolicy',
            location: null,
            reliesOnService: ['functions'],
            reliesOnCall: ['list'],
            properties: ['name']
        }
    },
    functionsv2: {
        getIamPolicy: {
            url: 'https://run.googleapis.com/v2/{name}:getIamPolicy',
            location: null,
            method: 'POST',
            reliesOnService: ['functionsv2'],
            reliesOnCall: ['list'],
            properties: ['name'],
            body: { options: { requestedPolicyVersion: 3 } }
        }
    },
    jobs: {
        get: { //https://dataflow.googleapis.com/v1b3/projects/{projectId}/jobs/{jobId}
            url: 'https://dataflow.googleapis.com/v1b3/projects/{projectId}/locations/{locationId}/jobs/{id}',
            reliesOnService: ['jobs'],
            reliesOnCall: ['list'],
            location: 'region',
            properties: ['id'],
            pagination: false,
        }
    },
    instanceGroups: {
        listInstances: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/{location}/instanceGroups/{name}/listInstances',
            method: 'POST',
            reliesOnService: ['instanceGroups'],
            reliesOnCall: ['aggregatedList'],
            properties: ['location','name'],
            filterObjKey: 'instanceGroups'
        },
        get: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/{location}/instanceGroups/{name}',
            reliesOnService: ['instanceGroups'],
            reliesOnCall: ['aggregatedList'],
            properties: ['location','name'],
            filterObjKey: 'instanceGroups'

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
        },
        getCmekSettings: {
            url: 'https://logging.googleapis.com/v2/organizations/{organizationId}/cmekSettings',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId']
        },
        essentialContacts: {
            url: 'https://essentialcontacts.googleapis.com/v1/organizations/{organizationId}/contacts',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId'],
            pagination: true,
            paginationKey: 'pageSize'
        },
        listAccessPolicies: {
            url: 'https://accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations/{organizationId}',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId'],
            pagination: true,
            paginationKey: 'pageSize',
            dataKey: 'accessPolicies'
        },
        sendIntegration: serviceMap['Resource Manager']
    },
    folders:{ // https://cloudresourcemanager.googleapis.com/v2/folders
        list: {
            url: 'https://cloudresourcemanager.googleapis.com/v2/folders?parent=organizations/{organizationId}',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['organizationId'],
            pagination: true,
            paginationKey: 'pageSize'
        }
    },
    apiKeys: {
        get: {
            url: 'https://apikeys.googleapis.com/v2/{name}',
            reliesOnService: ['apiKeys'],
            reliesOnCall: ['list'],
            properties: ['name']
        }
    },
    images: {
        getIamPolicy: {
            url: 'https://compute.googleapis.com/compute/v1/projects/{projectId}/global/images/{name}/getIamPolicy',
            reliesOnService: ['images'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        }
    },
    services: {
        listEnabled: {
            url: 'https://serviceusage.googleapis.com/v1/projects/{projectNumber}/services',
            reliesOnService: ['projects'],
            reliesOnCall: ['getWithNumber'],
            properties: ['projectNumber'],
            pagination: true,
            paginationKey: 'pageSize',
            reqParams: 'filter=state:ENABLED'
        }
    },
    groups: {
        list: {
            url: 'https://cloudidentity.googleapis.com/v1/groups?parent=customers/{directoryCustomerId}',
            location: null,
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['directoryCustomerId'],
            subObj: 'owner',
            pagination: false
        }
    },
    policies: {
        getProjectDenyPolicies: {// GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Fprojects%2projectId/denypolicies/policyId
            url:'https://iam.googleapis.com/v2/{name}',
            reliesOnService: ['policies'],
            reliesOnCall: ['projectDenyPolicies'],
            properties: ['name'],
            method: 'GET',
            pagination: false
        },
        orgDenyPolicies: {// GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Forganizations%252ForganizationId/denypolicies
            url: 'https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252F{name}/denypolicies',
            reliesOnService: ['organizations'],
            reliesOnCall: ['list'],
            properties: ['name'],
            encodeProperty: true,
            method: 'GET',
            pagination: false
        },
    },
    bigtable: {
        getIamPolicy: {//POST https://bigtableadmin.googleapis.com/v2/{resource=projects/*/instances/*}:getIamPolicy
            url: 'https://bigtableadmin.googleapis.com/v2/{name}:getIamPolicy',
            reliesOnService: ['bigtable'],
            reliesOnCall: ['list'],
            properties: ['name'],
            method: 'POST',
            pagination: false
        },
    },
    spanner: {
        getIamPolicy: {//POST https://spanner.googleapis.com/v1/{resource=projects/*/instances/*}:getIamPolicy
            url: 'https://spanner.googleapis.com/v1/{name}:getIamPolicy',
            reliesOnService: ['spanner'],
            reliesOnCall: ['list'],
            properties: ['name'],
            method: 'POST',
            pagination: false
        },
    },
    deployments: {
        getIamPolicy: {//GET https://www.googleapis.com/deploymentmanager/v2/projects/project/global/deployments/resource/getIamPolicy
            url: 'https://www.googleapis.com/deploymentmanager/v2/projects/{projectId}/global/deployments/{name}/getIamPolicy',
            reliesOnService: ['deployments'],
            reliesOnCall: ['list'],
            properties: ['name'],
            method: 'GET',
            pagination: false
        },
    },
    dataproc: {
        getIamPolicy: {//POST https://dataproc.googleapis.com/v1/{resource=projects/*/regions/*/operations/*}:getIamPolicy
            url: 'https://dataproc.googleapis.com/v1/projects/{projectId}/regions/{locationId}/clusters/{clusterName}:getIamPolicy',
            reliesOnService: ['dataproc'],
            reliesOnCall: ['list'],
            properties: ['clusterName'],
            method: 'POST',
            pagination: false
        },
    },
};

var tertiarycalls = {
    cryptoKeys: {
        getIamPolicy: {
            url: 'https://cloudkms.googleapis.com/v1/{name}:getIamPolicy',
            location: 'region',
            reliesOnService: ['cryptoKeys'],
            reliesOnCall: ['list'],
            properties: ['name'],
        }
    },
    bigqueryTables: {
        get: {
            url: 'https://bigquery.googleapis.com/bigquery/v2/projects/{projectId}/datasets/{datasetId}/tables/{tableId}',
            location: null,
            reliesOnService: ['bigqueryTables'],
            reliesOnCall: ['list'],
            properties: ['datasetId', 'tableId'],
            subObj: ['tableReference'],
            pagination: true,
            maxLimit: 50000
        }
    },
    groups: {
        get: {
            url: 'https://cloudidentity.googleapis.com/v1/{name}',
            location: null,
            reliesOnService: ['groups'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: false
        }
    },
    memberships: {
        list: {
            url: 'https://cloudidentity.googleapis.com/v1/{name}/memberships',
            location: null,
            reliesOnService: ['groups'],
            reliesOnCall: ['list'],
            properties: ['name'],
            pagination: true,
            paginationKey: 'nextPageToken'
        }
    },
    folders: { //https://cloudresourcemanager.googleapis.com/v2/{resource=folders/!*}:getIamPolicy
        getIamPolicy: {
            url: 'https://cloudresourcemanager.googleapis.com/v2/{name}:getIamPolicy',
            // name =  resource name of the Folder. Its format is folders/{folder_id}, for example: "folders/1234".
            reliesOnService: ['folders'],
            reliesOnCall: ['list'],
            properties: ['name'],
            method: 'POST',
            pagination: false
        },
    },
    policies: { // GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Forganizations%252ForganizationId/denypolicies/policyId
        getOrgDenyPolicies: {
            url: 'https://iam.googleapis.com/v2/{name}',
            reliesOnService: ['policies'],
            reliesOnCall: ['orgDenyPolicies'],
            properties: ['name'],
            method: 'GET',
            pagination: false
        },
        folderDenyPolicies: {// GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Ffolders%252FfolderId/denypolicies
            url: 'https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252F{name}/denypolicies',
            reliesOnService: ['folders'],
            reliesOnCall: ['list'],
            properties: ['name'],
            encodeProperty: true,
            method: 'GET',
            pagination: false
        },
    },
    organizations: {
        servicePerimeters: {
            url: 'https://accesscontextmanager.googleapis.com/v1/{name}/servicePerimeters',
            reliesOnService: ['organizations'],
            reliesOnCall: ['listAccessPolicies'],
            properties: ['name'],
            method: 'GET',
            pagination: true,
            dataKey: 'servicePerimeters'
        }
    }
};

var additionalCalls = {
    policies: {
        getFolderDenyPolicies: {// GET https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%252Ffolders%252FfolderId/denypolicies/policyId
            url: 'https://iam.googleapis.com/v2/{name}',
            reliesOnService: ['policies'],
            reliesOnCall: ['folderDenyPolicies'],
            properties: ['name'],
            method: 'GET',
            pagination: false
        },
    },
};

var specialcalls = {
    iam: {
        list: {
            pagination: true,
            reliesOnService: ['projects','folders','organizations','memberships','policies'],
            reliesOnCall: ['getIamPolicy','getProjectDenyPolicies','getOrgDenyPolicies','getFolderDenyPolicies']
        },
        sendIntegration: {
            integrationReliesOn: {
                serviceName: ['roles','projects','folders','organizations','memberships','policies']
            },
            enabled: true
        }
    }
};

module.exports = {
    calls: calls,
    postcalls: postcalls,
    tertiarycalls: tertiarycalls,
    specialcalls: specialcalls,
    additionalCalls:additionalCalls,
    serviceMap: serviceMap
};
