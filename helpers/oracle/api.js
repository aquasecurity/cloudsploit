/*
 enabled: send integration is enable or not
 isSingleSource: whether resource is single source or not

----------Bridge Side Data----------
 BridgeServiceName: it should be the api service name which we are storing in json file in s3 collection bucket. // this is the name of the service from the collection object Eg. 'vcn'
 BridgeCall: it should be the api call which we are storing in json file in s3 collection bucket. // Eg. 'list'
 BridgePluginCategoryName: it should be equivalent to Plugin Category Name as shown in  plugin
 BridgeProvider: it should be the cloud provider
                 Eg. 'aws', 'Azure', 'Google', 'Oracle'

 BridgeArnIdentifier: this is where the identifier is stored. it should be 'id' for Oracle.

 BridgeIdTemplate: no need to pass here

 BridgeResourceType: this should be type of the resource, fetch it from the id.
                     Eg. 'securitylist' // this comes from the id Eg. ocid1.securitylist.oc1.il-jerusalem-1.aaaaaaaa56vz65hmjox6vgzflw4lo5vcpyfgbffvlk6bt4aiac7bb4iir5ua

 BridgeResourceNameIdentifier: it should be the key of resource name/id data which we are storing in json file in s3 collection bucket.
                               Eg. displayName for Oracle

 Note: if there is no name then we have to pass the id.

 BridgeExecutionService: it should be equivalent to service name which we are sending from executor in payload data.  // This is the service we send in the executor for plugins
 BridgeCollectionService: it should be equivalent to service name which we are sending from collector in payload data. // this is how we save it in the collection Eg. 'instance'
 DataIdentifier: it should be the parent key field of data which we want to collect in json file in s3 collection bucket. // should always be 'data'

----------Processor Side Data----------
These fields should be according to the user and product manager, what they want to show in Inventory UI.
 InvAsset: 'networking' this should be the category
 InvService: 'Networking' category but capitalized
 InvResourceCategory: 'cloud_resources' // keep all as cloud_resources for now
 InvResourceType: 'virtual_cloud_network' the specific type of resource, could also be vcn

Note: For specific category add the category name otherwise it should be 'cloud_resource'

 Take the reference from the below map
*/

// Note: In Below service map add only single source resources.
// and service name should be plugin category.

var serviceMap = {
    'Networking':[
        {
            enabled: true, isSingleSource: true, InvAsset: 'networking', InvService: 'Networking',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'virtual_cloud_network', BridgeServiceName: 'vcn',
            BridgePluginCategoryName: 'oracle-Networking', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'vcn',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Networking',
            BridgeCollectionService: 'oracle-vcn', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'networking', InvService: 'Networking',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'security_list', BridgeServiceName: 'securitylist',
            BridgePluginCategoryName: 'oracle-Networking', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'securitylist',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Networking',
            BridgeCollectionService: 'oracle-securityList', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'networking', InvService: 'Networking',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'network_security_group', BridgeServiceName: 'networksecuritygroup',
            BridgePluginCategoryName: 'oracle-Networking', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'networksecuritygroup',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Networking',
            BridgeCollectionService: 'oracle-networkSecurityGroup', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'networking', InvService: 'Networking',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'load_balancer', BridgeServiceName: 'loadbalancer',
            BridgePluginCategoryName: 'oracle-Networking', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'loadbalancer',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Networking',
            BridgeCollectionService: 'oracle-loadBalancer', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'networking', InvService: 'Networking',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'subnet', BridgeServiceName: 'subnet',
            BridgePluginCategoryName: 'oracle-Networking', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'subnet',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Networking',
            BridgeCollectionService: 'oracle-subnet', DataIdentifier: 'data',
        },
    ],
    'Compute': [
        {
            enabled: true, isSingleSource: true, InvAsset: 'compute', InvService: 'Compute',
            InvResourceCategory: 'vm', InvResourceType: 'Compute', BridgeServiceName: 'instance',
            BridgePluginCategoryName: 'oracle-Compute', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'instance',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Compute',
            BridgeCollectionService: 'oracle-instance', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'compute', InvService: 'Compute',
            InvResourceCategory: 'vm', InvResourceType: 'Compute', BridgeServiceName: 'instancepool',
            BridgePluginCategoryName: 'oracle-Compute', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'instancepool',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Compute',
            BridgeCollectionService: 'oracle-instancePool', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'compute', InvService: 'Compute',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'boot_volume', BridgeServiceName: 'bootvolume',
            BridgePluginCategoryName: 'oracle-Compute', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'bootvolume',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Compute',
            BridgeCollectionService: 'oracle-bootVolume', DataIdentifier: 'data',
        },
    ],
    'Block Storage': [
        {
            enabled: true, isSingleSource: true, InvAsset: 'storage', InvService: 'Storage',
            InvResourceCategory: 'storage', InvResourceType: 'block_volume', BridgeServiceName: 'volume',
            BridgePluginCategoryName: 'oracle-Block Storage', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'volume',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Block Storage',
            BridgeCollectionService: 'oracle-volume', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'storage', InvService: 'Storage',
            InvResourceCategory: 'storage', InvResourceType: 'volume_group', BridgeServiceName: 'volumegroup',
            BridgePluginCategoryName: 'oracle-Block Storage', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'volumegroup',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Block Storage',
            BridgeCollectionService: 'oracle-volumeGroup', DataIdentifier: 'data',
        },
    ],
    'File Storage':
        {
            enabled: true, isSingleSource: true, InvAsset: 'storage', InvService: 'Storage',
            InvResourceCategory: 'storage', InvResourceType: 'file_system', BridgeServiceName: 'filesystem',
            BridgePluginCategoryName: 'oracle-File Storage', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'filesystem',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-File Storage',
            BridgeCollectionService: 'oracle-fileSystem', DataIdentifier: 'data',
        },
    'Object Store':
        {
            enabled: true, isSingleSource: true, InvAsset: 'storage', InvService: 'Storage',
            InvResourceCategory: 'storage', InvResourceType: 'object_store', BridgeServiceName: 'bucket',
            BridgePluginCategoryName: 'oracle-Object Store', BridgeProvider: 'Oracle', BridgeCall: 'get',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'bucket',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Object Store',
            BridgeCollectionService: 'oracle-bucket', DataIdentifier: 'data',
        },
    'Vaults':
        {
            enabled: true, isSingleSource: true, InvAsset: 'vaults', InvService: 'Vaults',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'key', BridgeServiceName: 'keys',
            BridgePluginCategoryName: 'oracle-Vaults', BridgeProvider: 'Oracle', BridgeCall: 'get',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'key',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Vaults',
            BridgeCollectionService: 'oracle-keys', DataIdentifier: 'data',
        },
    'Identity': [
        {
            enabled: true, isSingleSource: true, isIdentity: true, InvAsset: 'identity', InvService: 'Identity',
            InvResourceCategory: 'identity', InvResourceType: 'user', BridgeServiceName: 'user',
            BridgePluginCategoryName: 'oracle-Identity', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '{id}', BridgeResourceType: 'user',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'oracle-Identity',
            BridgeCollectionService: 'oracle-user', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'identity', InvService: 'Identity',
            InvResourceCategory: 'identity', InvResourceType: 'group', BridgeServiceName: 'group',
            BridgePluginCategoryName: 'oracle-Identity', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '{id}', BridgeResourceType: 'group',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'oracle-Identity',
            BridgeCollectionService: 'oracle-group', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'identity', InvService: 'Identity',
            InvResourceCategory: 'identity', InvResourceType: 'policy', BridgeServiceName: 'policy',
            BridgePluginCategoryName: 'oracle-Identity', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '{id}', BridgeResourceType: 'policy',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'oracle-Identity',
            BridgeCollectionService: 'oracle-policy', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'identity', InvService: 'Identity',
            InvResourceCategory: 'identity', InvResourceType: 'rule', BridgeServiceName: 'rules',
            BridgePluginCategoryName: 'oracle-Identity', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'eventrule',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Identity',
            BridgeCollectionService: 'oracle-rules', DataIdentifier: 'data',
        }
    ],
    'OKE':
        {
            enabled: true, isSingleSource: true, InvAsset: 'oke', InvService: 'OKE',
            InvResourceCategory: 'k8s_resource', InvResourceType: 'oke_cluster', BridgeServiceName: 'cluster',
            BridgePluginCategoryName: 'oracle-OKE', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'cluster',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'oracle-OKE',
            BridgeCollectionService: 'oracle-cluster', DataIdentifier: 'data',
        },
    'Database': [
        {
            enabled: true, isSingleSource: true, InvAsset: 'database', InvService: 'Database',
            InvResourceCategory: 'database', InvResourceType: 'database', BridgeServiceName: 'database',
            BridgePluginCategoryName: 'oracle-Database', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'database',
            BridgeResourceNameIdentifier: 'dbName', BridgeExecutionService: 'oracle-Database',
            BridgeCollectionService: 'oracle-database', DataIdentifier: 'data',
        },
        {
            enabled: true, isSingleSource: true, InvAsset: 'database', InvService: 'Database',
            InvResourceCategory: 'database', InvResourceType: 'db_system', BridgeServiceName: 'dbsystem',
            BridgePluginCategoryName: 'oracle-Database', BridgeProvider: 'Oracle', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'dbsystem',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'oracle-Database',
            BridgeCollectionService: 'oracle-dbSystem', DataIdentifier: 'data',
        },
    ]
};
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
        },
        sendIntegration: serviceMap['Networking'][0]

    },
    logGroup: {
        list: {
            api: 'logging',
            restVersion: '/20200531',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId']
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
        },
        sendIntegration: serviceMap['Compute'][0]
    },
    loadBalancer: {
        list: {
            api: 'loadBalance',
            restVersion: '/20170115',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId']
        },
        sendIntegration: serviceMap['Networking'][3]
    },
    cluster: {
        list: {
            api: 'oke',
            restVersion: '/20180222',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId']
        },
        sendIntegration: serviceMap['OKE']
    }, 
    user: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Identity'][0]
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
    cloudguardConfiguration: {
        get: {
            api: 'cloudguard',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20200131',
        }
    },
    group: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Identity'][1]
    },
    exportSummary: {
        list: {
            api: 'fileStorage',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20171215',
        }
    },
    fileSystem: {
        list: {
            api: 'fileStorage',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20171215',
        },
        sendIntegration: serviceMap['File Storage']
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
    defaultTags: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20160918'
        }
    },
    // waasPolicy: {
    //     list: {
    //         api: 'waas',
    //         restVersion: '/20181116',
    //         filterKey: ['compartmentId'],
    //         filterValue: ['compartmentId'],
    //     }
    // },
    rules: {
        list: {
            api: 'events',
            restVersion: '/20181201',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Identity'][4]
    },
    topics: {
        list: {
            api: 'notification',
            restVersion: '/20181201',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    subscriptions: {
        list: {
            api: 'notification',
            restVersion: '/20181201',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        }
    },
    policy: {
        list: {
            api: 'iam',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Identity'][2]
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
        },
        sendIntegration: serviceMap['Compute'][1]
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
        },
        sendIntegration: serviceMap['Compute'][2]
    },
    volume: {
        list: {
            api: 'core',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Block Storage'][0]
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
        },
        sendIntegration: serviceMap['Block Storage'][1]
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
        },
        sendIntegration: serviceMap['Networking'][2]
    },
    dbSystem: {
        list: {
            api: 'database',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
        },
        sendIntegration: serviceMap['Database'][1]
    },
    vault: {
        list: {
            api: 'kms',
            filterKey: ['compartmentId'],
            filterValue: ['compartmentId'],
            restVersion: '/20180608',
        }
    },
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
        },
        sendIntegration: serviceMap['Networking'][4]
    },
    securityList: {
        list: {
            api: 'core',
            reliesOnService: ['vcn'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'vcnId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        },
        sendIntegration: serviceMap['Networking'][1]
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
    apiKey: {
        list: {
            api: 'iam',
            reliesOnService: ['user'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'userId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    authToken: {
        list: {
            api: 'iam',
            reliesOnService: ['user'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'userId'],
            filterValue: ['compartmentId', 'id'],
            filterConfig: [true, false],
        }
    },
    customerSecretKey: {
        list: {
            api: 'iam',
            reliesOnService: ['user'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'userId'],
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
        },
        sendIntegration: serviceMap['Database'][0]
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
    keys: {
        list: {
            api: 'kms',
            reliesOnService: ['vault'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'managementEndpoint'],
            filterValue: ['compartmentId', 'managementEndpoint'],
            restVersion: '/20180608'
        }
    },
    log: {
        list: {
            api: 'logging',
            reliesOnService: ['logGroup'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'id'],
            filterValue: ['compartmentId', 'id'],
            restVersion: '/20200531'
        }
    },
    cluster: {
        get: {
            api: 'oke',
            reliesOnService: ['cluster'],
            reliesOnCall: ['list'],
            restVersion: '/20180222',
            filterKey: ['id'],
            filterValue: ['id'],
            filterConfig: [false]
        },
    }
};

// Important Note: All relies must be passed in an array format []
var finalcalls = {
    bucket: {
        get: {
            api: 'objectStore',
            reliesOnService: ['bucket'],
            reliesOnCall: ['list'],
            filterKey: ['bucketName', 'namespaceName'],
            filterValue: ['name','namespace'],
            restVersion: '',
        },
        sendIntegration: serviceMap['Object Store']
    },
    keys: {
        get: {
            api: 'kms',
            reliesOnService: ['keys'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'id'],
            filterValue: ['compartmentId', 'id'],
            restVersion: '/20180608'
        },
        sendIntegration: serviceMap['Vaults']
    },
    keyVersions: {
        list: {
            api: 'kms',
            reliesOnService: ['keys'],
            reliesOnCall: ['list'],
            filterKey: ['compartmentId', 'id'],
            filterValue: ['compartmentId', 'id'],
            restVersion: '/20180608'
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

module.exports = {
    calls: calls,
    postcalls: postcalls,
    finalcalls: finalcalls,
    serviceMap: serviceMap
};
