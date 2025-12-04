// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    alertPolicies: {
        list: 'name'
    },
    apiKeys: {
        list: 'name',
        get: 'name'
    },
    autoscalers: {
        aggregatedList: ''
    },
    buckets: {
        list: '',
        getIamPolicy: ''
    },
    backendServices: {
        list: 'id'
    },
    backupRuns: {
        list: ''
    },
    bigtable: {
        list: 'name'
    },
    compute: {
        list: '',
        aggregatedList: ''
    },
    cryptoKeys: {
        list: 'name'
    },
    datasets: {
        list: '',
        get: ''
    },
    dataproc: {
        list: ''
    },
    deployments: {
        list: ''
    },
    disks: {
        aggregatedList: '',
        list: ''
    },
    firewalls: {
        list: ''
    },
    functions: {
        list: 'name'
    },
    functionsv2: {
        list: 'name',
        getIamPolicy: 'name'
    },
    instanceGroups: {
        aggregatedList: ''
    },
    instanceGroupManagers: {
        list: ''
    },
    images: {
        list: '',
        getIamPolicy: ''
    },
    jobs: {
        list: '',
        get: ''
    },
    keys: {
        list: 'name'
    },
    keyRings: {
        list: 'name',
    },
    kubernetes: {
        list: ''
    },
    managedZones: {
        list: ''
    },
    metrics: {
        list: 'metricDescriptor.name'
    },
    networks: {
        list: ''
    },
    organizations: {
        list: '',
        listOrgPolicies: ''
    },
    policies: {
        list: ''
    },
    projects:{
        getIamPolicy: '',
        get: ''
    },
    resourcePolicies: {
        list: 'id'
    },
    serviceAccounts: {
        list: 'name'
    },
    sinks: {
        list: ''
    },
    sql: {
        list: 'name'
    },
    spanner: {
        list: ''
    },
    snapshots: {
        list: ''
    },
    subnetworks: {
        list: ''
    },
    subscriptions: {
        list: 'name'
    },
    targetHttpProxies: {
        list: 'id'
    },
    topics: {
        list: 'name'
    },
    urlMaps: {
        list: 'id'
    },
    users: {
        list: ''
    },
    vertexAI: {
        listDatasets: 'name',
        listModels: 'name'
    }
};