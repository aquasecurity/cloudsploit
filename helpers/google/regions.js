// Source: https://cloud.google.com/about/locations/

var regions = [
    'us-east1',                     // South Carolina
    'us-east4',                     // North Virginia
    'us-west1',                     // Oregon
    'us-west2',                     // Los Angeles
    'us-west3',                     // Salt Lake City
    'us-west4',                     // Las Vegas
    'us-central1',                  // Iowa
    'northamerica-northeast1',      // Montreal
    'northamerica-northeast2',      // Toronto
    'southamerica-east1',           // Sao Paulo
    'europe-west1',                 // Belgium
    'europe-west2',                 // London
    'europe-west3',                 // Frankfurt
    'europe-west4',                 // Netherlands
    'europe-west6',                 // Zurich
    'europe-north1',                // Finland
    'europe-central2',              // Warsaw
    'asia-south1',                  // Mumbai
    'asia-south2',                  // Delhi
    'asia-southeast1',              // Singapore
    'asia-southeast2',              // Jakarta
    'asia-east1',                   // Taiwan
    'asia-east2',                   // Hong Kong
    'asia-northeast1',              // Tokyo
    'asia-northeast2',              // Osaka
    'asia-northeast3',              // Seoul
    'australia-southeast1',         // Sydney
    'australia-southeast2',         // Melbourne
];

var zones = {
    'us-east1'                      : ['us-east1-b', 'us-east1-c', 'us-east1-d'],
    'us-east4'                      : ['us-east4-a', 'us-east4-b', 'us-east4-c'],
    'us-west1'                      : ['us-west1-a', 'us-west1-b', 'us-west1-c'],
    'us-west2'                      : ['us-west2-a', 'us-west2-b', 'us-west2-c'],
    'us-west3'                      : ['us-west3-a', 'us-west3-b', 'us-west3-c'],
    'us-west4'                      : ['us-west4-a', 'us-west4-b', 'us-west4-c'],
    'us-central1'                   : ['us-central1-a', 'us-central1-b', 'us-central1-c', 'us-central1-f'],
    'northamerica-northeast1'       : ['northamerica-northeast1-a', 'northamerica-northeast1-b', 'northamerica-northeast1-c'],
    'northamerica-northeast2'       : ['northamerica-northeast2-a', 'northamerica-northeast2-b', 'northamerica-northeast2-c'],
    'southamerica-east1'            : ['southamerica-east1-a', 'southamerica-east1-b', 'southamerica-east1-c'],
    'europe-west1'                  : ['europe-west1-b', 'europe-west1-c', 'europe-west1-d'],
    'europe-west2'                  : ['europe-west2-a', 'europe-west2-b', 'europe-west2-c'],
    'europe-west3'                  : ['europe-west3-a', 'europe-west3-b', 'europe-west3-c'],
    'europe-west4'                  : ['europe-west4-a', 'europe-west4-b', 'europe-west4-c'],
    'europe-west5'                  : ['europe-west5-a', 'europe-west5-b', 'europe-west5-c'],
    'europe-west6'                  : ['europe-west6-a', 'europe-west6-b', 'europe-west6-c'],
    'europe-north1'                 : ['europe-north1-a', 'europe-north1-b', 'europe-north1-c'],
    'europe-central2'               : ['europe-central2-a', 'europe-central2-b', 'europe-central2-c'],
    'asia-south1'                   : ['asia-south1-a', 'asia-south1-b', 'asia-south1-c'],
    'asia-south2'                   : ['asia-south2-a', 'asia-south2-b', 'asia-south2-c'],
    'asia-southeast1'               : ['asia-southeast1-a', 'asia-southeast1-b', 'asia-southeast1-c'],
    'asia-southeast2'               : ['asia-southeast2-a', 'asia-southeast2-b', 'asia-southeast2-c'],
    'asia-east1'                    : ['asia-east1-a', 'asia-east1-b', 'asia-east1-c'],
    'asia-east2'                    : ['asia-east2-a', 'asia-east2-b', 'asia-east2-c'],
    'asia-northeast1'               : ['asia-northeast1-a', 'asia-northeast1-b', 'asia-northeast1-c'],
    'asia-northeast2'               : ['asia-northeast2-a', 'asia-northeast2-b', 'asia-northeast2-c'],
    'asia-northeast3'               : ['asia-northeast3-a', 'asia-northeast3-b', 'asia-northeast3-c'],
    'australia-southeast1'          : ['australia-southeast1-a', 'australia-southeast1-b', 'australia-southeast1-c'],
    'australia-southeast2'          : ['australia-southeast2-a', 'australia-southeast2-b', 'australia-southeast2-c']
};

module.exports = {
    all_regions: regions,
    zones: zones,
    disks: ['global', ...regions],
    images: ['global'],
    keyRings: ['global', ...regions],
    cryptoKeys: ['global', ...regions],
    securityPolicies: ['global'],
    resourcePolicies: regions,
    snapshots: ['global'],
    firewalls: ['global'],
    buckets: ['global'],
    instances: {
        compute: regions,
        sql: ['global'],
        spanner: ['global']
    },
    functions: [
        'us-east1', 'us-east4', 'us-west2', 'us-west3', 'us-west4', 'us-central1', 'northamerica-northeast1', 'southamerica-east1',
        'europe-west1', 'europe-west2', 'europe-west3', 'europe-west6', 'europe-central2', 'asia-south1', 'asia-southeast1', 'asia-southeast2',
        'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3', 'australia-southeast1'
    ],
    instanceTemplates: ['global'],
    networks: ['global'],
    backendServices: ['global'],
    healthChecks: ['global'],
    targetHttpProxies: ['global'],
    instanceGroups: ['global'],
    autoscalers: ['global'],
    subnetworks: regions,
    projects: ['global'],
    clusters: ['global'],
    managedZones: ['global'],
    metrics: ['global'],
    alertPolicies: ['global'],
    serviceAccounts: ['global'],
    keys: ['global'],
    sinks: ['global'],
    users: ['global'],
    backupRuns: ['global'],
    datasets: ['global'],
    policies: ['global'],
    topics: ['global'],
    subscriptions: ['global'],
    jobs: regions,
    organizations: ['global'],
    deployments: ['global'],
    urlMaps: ['global'],
};
