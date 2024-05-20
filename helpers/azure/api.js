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

 BridgeIdTemplate:  this should be the template for creating the resource id.
                    supported values: name, region, cloudAccount, project, id

 BridgeResourceType: this should be type of the resource, fetch it from the id.
                     Eg. 'servers'

 BridgeResourceNameIdentifier: it should be the key of resource name/id data which we are storing in json file in  s3 collection bucket.
                               Eg. 'Name/name' or 'Id/id'

 Note: if there is no name then we have to pass the id.

 BridgeExecutionService: it should be equivalent to service name which we are sending from executor in payload data.
 BridgeCollectionService: it should be equivalent to service name which we are sending from collector in payload data.
 DataIdentifier: it should be the parent key field of data which we want to collect in json file in s3 collection bucket.

----------Processor Side Data----------
These fields should be according to the user and product manager, what they want to show in Inventory UI.
 InvAsset: 'LogAlerts'
 InvService: 'LogAlerts'
 InvResourceCategory: 'cloud_resources'
    Note: For specific category add the category name otherwise it should be 'cloud_resource'

 InvResourceType: 'LogAlerts'
    If you need that your resource type to be two words with capital letter only on first letter of the word (for example: Key Vaults), you should supply the resource type with a space delimiter.
    If you need that your resource type to be two words and the the first word should be in capital letters (for example: CDN Profiles), you should supply the resource type with snake case delimiter

 Take the reference from the below map
*/

// Note: In Below service map add only single source resources.
// and service name should be plugin category.

var serviceMap = {
    'Redis Cache':
        {
            enabled: true, isSingleSource: true, InvAsset: 'redisCaches', InvService: 'redisCaches',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Redis Cache', BridgeServiceName: 'rediscaches',
            BridgePluginCategoryName: 'Redis Cache', BridgeProvider: 'Azure', BridgeCall: 'listBySubscription',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'Redis',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Redis Cache',
            BridgeCollectionService: 'rediscaches', DataIdentifier: 'data',
        },
    'CDN Profiles':
        {
            enabled: true, isSingleSource: true, InvAsset: 'cdnProfiles', InvService: 'cdnProfiles',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'CDN_Profiles', BridgeServiceName: 'profiles',
            BridgePluginCategoryName: 'CDN Profiles', BridgeProvider: 'Azure', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'profiles',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'CDN Profiles',
            BridgeCollectionService: 'profiles', DataIdentifier: 'data',
        },
    'Cosmos DB':
        {
            enabled: true, isSingleSource: true, InvAsset: 'cosmosdb', InvService: 'cosmosDB',
            InvResourceCategory: 'database', InvResourceType: 'cosmos_DB', BridgeServiceName: 'databaseaccounts',
            BridgePluginCategoryName: 'Cosmos DB', BridgeProvider: 'Azure', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'databaseAccounts',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Cosmos DB',
            BridgeCollectionService: 'databaseaccounts', DataIdentifier: 'data',
        },
    'Key Vaults':
        {
            enabled: true, isSingleSource: true, InvAsset: 'vaults', InvService: 'keyVaults',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'key vaults', BridgeServiceName: 'vaults',
            BridgePluginCategoryName: 'Key Vaults', BridgeProvider: 'Azure', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'vaults',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Key Vaults',
            BridgeCollectionService: 'vaults', DataIdentifier: 'data',
        },
    'Load Balancer':
        {
            enabled: true, isSingleSource: true, InvAsset: 'loadBalancer', InvService: 'loadBalancer',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'load_balancer', BridgeServiceName: 'loadbalancers',
            BridgePluginCategoryName: 'Load Balancer', BridgeProvider: 'Azure', BridgeCall: 'listAll',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'loadBalancers',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Load Balancer',
            BridgeCollectionService: 'loadbalancers', DataIdentifier: 'data',
        },
    'Log Alerts':
        {
            enabled: true, isSingleSource: true, InvAsset: 'logAlerts', InvService: 'logAlerts',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'log alerts', BridgeServiceName: 'activitylogalerts',
            BridgePluginCategoryName: 'Log Alerts', BridgeProvider: 'Azure', BridgeCall: 'listBySubscriptionId',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'activityLogAlerts',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Log Alerts',
            BridgeCollectionService: 'activitylogalerts', DataIdentifier: 'data',
        },
    'Network Watcher':
        {
            enabled: true, isSingleSource: true, InvAsset: 'networkWatcher', InvService: 'networkWatcher',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'network_watcher', BridgeServiceName: 'networkwatchers',
            BridgePluginCategoryName: 'Network Watcher', BridgeProvider: 'Azure', BridgeCall: 'listAll',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'networkWatchers',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Network Watcher',
            BridgeCollectionService: 'networkwatchers', DataIdentifier: 'data',
        },
    'Azure Policy':
        {
            enabled: true, isSingleSource: true, InvAsset: 'azurePolicy', InvService: 'azurePolicy',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'azure_policy', BridgeServiceName: 'policyassignments',
            BridgePluginCategoryName: 'Azure Policy', BridgeProvider: 'Azure', BridgeCall: 'list',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'policyAssignments',
            BridgeResourceNameIdentifier: 'displayName', BridgeExecutionService: 'Azure Policy',
            BridgeCollectionService: 'policyassignments', DataIdentifier: 'data',
        },
    'Virtual Networks':
        {
            enabled: true, isSingleSource: true, InvAsset: 'virtual_network', InvService: 'virtual_network',
            InvResourceCategory: 'cloud_resources', InvResourceType: 'Virtual Network', BridgeServiceName: 'virtualnetworks',
            BridgePluginCategoryName: 'Virtual Networks', BridgeProvider: 'Azure', BridgeCall: 'listAll',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'virtualNetworks',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Virtual Networks',
            BridgeCollectionService: 'virtualnetworks', DataIdentifier: 'data',
        },
    'Queue Service':
        {
            enabled: true, isSingleSource: true, InvAsset: 'queueService', InvService: 'queueService',
            InvResourceCategory: 'storage', InvResourceType: 'queue_service', BridgeServiceName: 'queueservice',
            BridgePluginCategoryName: 'Queue Service', BridgeProvider: 'Azure', BridgeCall: 'getQueueAcl',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'queueService',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Queue Service',
            BridgeCollectionService: 'queueservice', DataIdentifier: 'data',
        },
    'Table Service':
        {
            enabled: true, isSingleSource: true, InvAsset: 'tableService', InvService: 'tableService',
            InvResourceCategory: 'storage', InvResourceType: 'table_service', BridgeServiceName: 'tableservice',
            BridgePluginCategoryName: 'Table Service', BridgeProvider: 'Azure', BridgeCall: 'getTableAcl',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'tableService',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'Table Service',
            BridgeCollectionService: 'tableservice', DataIdentifier: 'data',
        },
    'File Service':
        {
            enabled: true, isSingleSource: true, InvAsset: 'fileService', InvService: 'fileService',
            InvResourceCategory: 'storage', InvResourceType: 'file_service', BridgeServiceName: 'fileservice',
            BridgePluginCategoryName: 'File Service', BridgeProvider: 'Azure', BridgeCall: 'listSharesSegmented',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'fileService',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'File Service',
            BridgeCollectionService: 'fileservice', DataIdentifier: 'data',
        },
    'SQL Databases':
        {
            enabled: true, isSingleSource: true, InvAsset: 'database', InvService: 'sql',
            InvResourceCategory: 'database', InvResourceType: 'sql_database', BridgeServiceName: 'databases',
            BridgePluginCategoryName: 'SQL Databases', BridgeProvider: 'Azure', BridgeCall: 'listByServer',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'databases',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'SQL Databases',
            BridgeCollectionService: 'databases', DataIdentifier: 'data',
        },
    'AI & ML': 
        {
            enabled: true, isSingleSource: true, InvAsset: 'account', InvService: 'openAI',
            InvResourceCategory: 'ai&ml', InvResourceType: 'OpenAI Accounts', BridgeProvider: 'Azure', 
            BridgeServiceName: 'openAI', BridgePluginCategoryName: 'AI & ML',
            BridgeArnIdentifier: '', BridgeIdTemplate: '', BridgeResourceType: 'accounts',
            BridgeResourceNameIdentifier: 'name', BridgeExecutionService: 'AI & ML',
            BridgeCollectionService: 'openai', BridgeCall: 'listAccounts', DataIdentifier: 'data',
        },
};

// Standard calls that contain top-level operations
var calls = {
    resourceGroups: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2019-10-01'
        }
    },
    advisor: {
        recommendationsList: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Advisor/recommendations?api-version=2020-01-01'
        }
    },
    activityLogAlerts: {
        listBySubscriptionId: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/activityLogAlerts?api-version=2020-10-01'
        },
        sendIntegration: serviceMap['Log Alerts']
    },
    logAnalytics: {
        listWorkspaces: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01'
        }
    },
    storageAccounts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01',
            rateLimit: 3000
        }
    },
    containerApps:{
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.App/containerApps?api-version=2023-05-01'
        }
    },
    appConfigurations: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.AppConfiguration/configurationStores?api-version=2023-03-01'
        }
    },
    virtualNetworks: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2020-03-01'
        },
        sendIntegration: serviceMap['Virtual Networks']
    },
    natGateways: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/natGateways?api-version=2020-11-01'
        }
    },
    virtualMachines: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01',
            paginate: 'nextLink'
        }
    },
    publicIpAddresses: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-06-01'
        }
    },
    images: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/images?api-version=2022-08-01',
            paginate: 'nextLink'
        }
    },
    vmScaleSet: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2022-08-01',
            paginate: 'nextLink'
        }
    },
    snapshots: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/snapshots?api-version=2020-12-01'
        }
    },
    disks: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/disks?api-version=2023-04-02'
        }
    },
    networkSecurityGroups: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2020-03-01'
        }
    },
    networkInterfaces: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2020-11-01'
        }
    },
    vaults: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2019-09-01'
        },
        sendIntegration: serviceMap['Key Vaults'],
    },
    recoveryServiceVaults: {
        listBySubscriptionId: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults?api-version=2016-06-01'
        }
    },
    resources: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/resources?api-version=2021-04-01'
        },
    },
    redisCaches: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Cache/redis?api-version=2023-08-01'
        },
        sendIntegration: serviceMap['Redis Cache']
    },
    routeTables: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/routeTables?api-version=2022-07-01'
        }
    },
    managedClusters: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=2020-03-01'
        }
    },
    networkWatchers: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkWatchers?api-version=2022-01-01'
        },
        sendIntegration: serviceMap['Network Watcher']
    },
    policyAssignments: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments?api-version=2019-09-01',
        },
        sendIntegration: serviceMap['Azure Policy']
    },
    policyDefinitions: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01'
        }
    },
    webApps: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Web/sites?api-version=2019-08-01'
        }
    },
    appServiceCertificates: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Web/certificates?api-version=2019-08-01'
        }
    },
    logProfiles: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/logprofiles?api-version=2016-03-01'
        }
    },
    profiles: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Cdn/profiles?api-version=2024-02-01'
        },
        sendIntegration: serviceMap['CDN Profiles']
    },
    autoProvisioningSettings: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview'
        }
    },
    applicationGateway: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways?api-version=2022-07-01'
        }
    },
    securityContacts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2017-08-01-preview',
            ignoreLocation: true
        }
    },
    securityContactv2: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview',
            ignoreLocation: true,
            hasListResponse: true
        }
    },
    subscriptions: {
        listLocations: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/locations?api-version=2020-01-01'
        },
        get: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}?api-version=2020-01-01',
            getCompleteResponse: true,
        }
    },
    roleDefinitions: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01'
        }
    },
    managementLocks: {
        listAtSubscriptionLevel: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/locks?api-version=2016-09-01'
        }
    },
    loadBalancers: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2020-03-01'
        },
        sendIntegration: serviceMap['Load Balancer']
    },
    users: {
        list: {
            url: 'https://graph.microsoft.com/v1.0/users',
            graph: true
        }
    },
    applications: {
        list: {
            url: 'https://graph.microsoft.com/v1.0/applications/',
            graph: true,
        }
    },
    automationAccounts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01'
        }
    },
    registries: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview'
        }
    },
    pricings: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2018-06-01'
        }
    },
    availabilitySets: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/availabilitySets?api-version=2019-12-01'
        }
    },
    virtualMachineScaleSets: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2023-07-01'
        }
    },
    bastionHosts: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/bastionHosts?api-version=2022-09-01'
        }
    },
    wafPolicies: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies?api-version=2022-07-01'
        }
    },
    autoscaleSettings: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/autoscalesettings?api-version=2015-04-01'
        }
    },
    diagnosticSettingsOperations: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview'
        }
    },
    servers: {
        listSql: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview'
        },
        listMysql: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/servers?api-version=2017-12-01'
        },
        listMysqlFlexibleServer: {
            url : 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforMySQL/flexibleServers?api-version=2021-05-01'
        },
        listPostgres: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/servers?api-version=2017-12-01'
        },
        listPostgresFlexibleServer: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2022-12-01'
        }
    },
    databaseAccounts: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2020-06-01-preview'
        },
        sendIntegration: serviceMap['Cosmos DB']
    },
    securityCenter: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/settings?api-version=2021-06-01'
        }
    },
    publicIPAddresses: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/publicIPAddresses?api-version=2021-08-01'
        }
    },
    privateDnsZones: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/privateDnsZones?api-version=2018-09-01'
        }
    },
    privateEndpoints: {
        listBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/privateEndpoints?api-version=2022-01-01'
        }
    },
    eventGrid: {
        listDomains: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.EventGrid/domains?api-version=2023-12-15-preview'
        }
    },
    eventHub: {
        listEventHub: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.EventHub/namespaces?api-version=2022-10-01-preview'
        }
    },
    serviceBus: {
        listNamespacesBySubscription: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.ServiceBus/namespaces?api-version=2022-10-01-preview'
        }
    },
    mediaServices:{
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Media/mediaservices?api-version=2023-01-01'
        }

    },
    computeGalleries: { 
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Compute/galleries?api-version=2022-08-03'
        }
    },
    openAI: {
        listAccounts: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01'
        },
        sendIntegration: serviceMap['AI & ML']
    },
    databricks: {
        listWorkspaces: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Databricks/workspaces?api-version=2023-02-01'
        }
    },
    // For CIEM
    aad: {
        listRoleAssignments: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01'
        },
        listDenyAssignments: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/denyAssignments?api-version=2022-04-01'
        }
    },
    // For CIEM
    groups: {
        list: {
            url: 'https://graph.microsoft.com/v1.0/groups',
            graph: true
        }
    },
    // For CIEM
    servicePrincipals: {
        list: {
            url: 'https://graph.microsoft.com/v1.0/servicePrincipals',
            graph: true
        }
    },
    classicFrontDoors: {
        list: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/frontDoors?api-version=2019-05-01'
        }
    },
    afdWafPolicies: {
        listAll: {
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies?api-version=2022-05-01'

        }
    },

};

var postcalls = {
    //For CIEM
    aad: {
        getGroupMembers: {
            reliesOnPath: 'groups.list',
            properties: ['id'],
            url: 'https://graph.microsoft.com/v1.0/groups/{id}/members',
            graph: true
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['roleDefinitions','users','groups','servicePrincipals']
            }
        }
    },
    recoveryServiceVaults: {
        getRecoveryServiceVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2022-04-01'
        }
    },
    webhooks: {
        listByAutomationAccounts: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/webhooks?api-version=2015-10-31'
        }
    },
    accountVariables: {
        listByAutomationAccounts: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/variables?api-version=2023-11-01'
        }
    },
    availabilitySets:{
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Compute/availabilitySets?api-version=2020-12-01'
        }
    },
    advancedThreatProtection: {
        get: {
            reliesOnPath: 'databaseAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Security/advancedThreatProtectionSettings/current?api-version=2017-08-01-preview'
        },
        listPostgresFlexibleServer: {
            reliesOnPath: 'servers.listPostgresFlexibleServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/advancedThreatProtectionSettings?api-version=2023-06-01-preview'
        }
    },
    sourceControls: {
        listByAutomationAccounts: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/sourceControls?api-version=2023-11-01'
        }
    },
    automationAccounts:{
        get: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2023-11-01'
        }
    },
    backupProtectedItems: {
        listByVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupProtectedItems?api-version=2019-05-13'
        }
    },
    backupPolicies: {
        listByVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupPolicies?api-version=2019-05-13'
        }
    },
    serverBlobAuditingPolicies: {
        get: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/auditingSettings?api-version=2021-11-01'
        }
    },
    serverSecurityAlertPolicies: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/securityAlertPolicies?api-version=2017-03-01-preview'
        }
    },

    advancedThreatProtectionSettings: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/advancedThreatProtectionSettings?api-version=2021-11-01-preview'
        }
    },
    vulnerabilityAssessments: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/vulnerabilityAssessments?api-version=2021-02-01-preview'
        }
    },
    failoverGroups: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/failoverGroups?api-version=2021-02-01-preview'
        }
    },
    serverAutomaticTuning: {
        get: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/automaticTuning/current?api-version=2020-08-01-preview'
        }
    },
    certificates: {
        listByAutomationAccounts: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/certificates?api-version=2023-11-01'
        }
    },  
    flowLogs: {
        list: {
            reliesOnPath: 'networkWatchers.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/flowLogs?api-version=2020-11-01'
        }
    },
    virtualNetworkPeerings: {
        list: {
            reliesOnPath: 'virtualNetworks.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualNetworkPeerings?api-version=2020-11-01'
        }
    },
    flexibleServersConfigurations: {
        listByServer: {
            reliesOnPath: 'servers.listMysqlFlexibleServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/configurations?api-version=2021-05-01'
        },
        listByPostgresServer: {
            reliesOnPath: 'servers.listPostgresFlexibleServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/configurations?api-version=2022-12-01'
        },
    },
    serverAdministrators: {
        list: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/administrators?api-version=2017-12-01'
        }
    },
    recordSets: {
        list: {
            reliesOnPath: 'privateDnsZones.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/ALL?api-version=2018-09-01'
        }
    },
    virtualMachines: {
        get: {
            reliesOnPath: 'virtualMachines.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2020-12-01'
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['networkInterfaces', 'publicIPAddresses', 'recordSets']
            }
        }
    },
    virtualMachineExtensions: {
        list: {
            reliesOnPath: 'virtualMachines.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/extensions?api-version=2019-12-01'
        }
    },
    virtualMachineScaleSetVMs: {
        list: {
            reliesOnPath: 'virtualMachineScaleSets.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualMachines?api-version=2020-12-01'
        }
    },
    virtualNetworkGateways: {
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2020-11-01'
        }
    },
    networkGatewayConnections: {
        listByResourceGroup: {
            reliesOnPath: 'resourceGroups.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/Microsoft.Network/connections?api-version=2020-11-01'
        }
    },
    blobContainers: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices/default/containers?api-version=2019-06-01',
            rateLimit: 3000,
            limit: 20000
        }
    },
    blobServices: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices?api-version=2019-06-01',
            rateLimit: 3000
        },
        getServiceProperties: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices/default?api-version=2019-06-01',
            rateLimit: 500
        }
    },
    fileShares: {
        list: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/fileServices/default/shares?api-version=2023-01-01',
            rateLimit: 3000
        }
    },
    storageAccounts: {
        listKeys: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/listKeys?api-version=2019-06-01',
            post: true,
            rateLimit: 3000
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['storageAccounts', 'blobServices', 'blobContainers', 'fileShares']
            },
        }
    },
    encryptionProtectors: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/encryptionProtector?api-version=2015-05-01-preview'
        },
    },
    webApps: {
        getAuthSettings: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config/authsettings/list?api-version=2019-08-01',
            post: true
        },
        listConfigurations: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config?api-version=2019-08-01'
        },
        listAppSettings: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config/appsettings/list?api-version=2021-02-01',
            post: true
        },
        getBackupConfiguration: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config/backup/list?api-version=2021-02-01',
            post: true
        }
    },
    containerApps: {
        getAuthSettings : {
            reliesOnPath: 'containerApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/authConfigs?api-version=2023-05-01',
        }
    }, 
    endpoints: {
        listByProfile: {
            reliesOnPath: 'profiles.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/endpoints?api-version=2019-04-15'
        }
    },
    customDomain: {
        listByFrontDoorProfiles: {
            reliesOnPath: 'profiles.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/customDomains?api-version=2021-06-01'
        }
    },
    vaults: {
        getKeys: {
            reliesOnPath: 'vaults.list',
            properties: ['vaultUri'],
            url: '{vaultUri}keys?api-version=7.0',
            vault: true
        },
        getSecrets: {
            reliesOnPath: 'vaults.list',
            properties: ['vaultUri'],
            url: '{vaultUri}secrets?api-version=7.0',
            vault: true
        },
        getCertificates: {
            reliesOnPath: 'vaults.list',
            properties: ['vaultUri'],
            url: '{vaultUri}certificates?api-version=7.3',
            vault: true
        }
    },
    databases: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/databases?api-version=2023-02-01-preview'
        },
        sendIntegration: serviceMap['SQL Databases']
    },
    serverAzureADAdministrators: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/administrators?api-version=2014-04-01'
        }
    },
    usages: {
        list: {
            reliesOnPath: 'subscriptions.listLocations',
            properties: ['name'],
            url: 'https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/locations/{name}/usages?api-version=2020-03-01'
        }
    },
    firewallRules: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/firewallRules?api-version=2019-06-01-preview'
        },
        listByServerMySQL: {
            reliesOnPath: 'servers.listMysql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/firewallRules?api-version=2017-12-01'
        },
        listByServerPostgres: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/firewallRules?api-version=2017-12-01'
        },
        listByFlexibleServerPostgres: {
            reliesOnPath: 'servers.listPostgresFlexibleServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/firewallRules?api-version=2022-12-01'
        }
    },
    outboundFirewallRules: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/outboundFirewallRules?api-version=2022-02-01-preview'
        }
    },
    virtualNetworkRules: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualNetworkRules?api-version=2019-06-01-preview'
        },
        listByServerMySQL: {
            reliesOnPath: 'servers.listMysql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualNetworkRules?api-version=2017-12-01'
        },
        listByServerPostgres: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/virtualNetworkRules?api-version=2017-12-01'
        }
    },
    managedClusters: {
        getUpgradeProfile: {
            reliesOnPath: 'managedClusters.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/upgradeProfiles/default?api-version=2020-03-01'
        },
        pools: {
            reliesOnPath: 'managedClusters.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/agentPools?api-version=2022-03-01'
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['managedClusters', 'virtualNetworks', 'virtualNetworkPeerings']
            },
        }
    },
    functions: {
        config: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/config?api-version=2022-03-01'
        },
        usages: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/usages?api-version=2022-03-01'
        },
        list: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/functions?api-version=2021-03-01'
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['webApps']
            }
        }
    },
    registries: {
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['replications']
            }
        }
    },
    dbServers: {
        getSQL: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2022-05-01-preview'
        },
        getMySQL: {
            reliesOnPath: 'servers.listMysql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2017-12-01'
        },
        getPostgres: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2017-12-01'
        },
        sendIntegration: {
            enabled: true,
            integrationReliesOn: {
                serviceName: ['privateEndpoints','firewallRules', 'virtualNetworkRules',
                    'networkInterfaces', 'failoverGroups', 'outboundFirewallRules']
            }
        }
    },
    replications: {
        list: {
            reliesOnPath: 'registries.list',
            properties: ['id'],
            url: 'https://management.azure.com{id}/replications?api-version=2019-05-01'
        }
    },
    configurations: {
        listByServer: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/configurations?api-version=2017-12-01'
        }
    },
    mediaServices: {
        listContentKeyPolicies: {
            reliesOnPath: 'mediaServices.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/contentKeyPolicies?api-version=2023-01-01'
        },
        get: {
            reliesOnPath: 'mediaServices.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}?api-version=2023-01-01'
        }
    },
    afdSecurityPolicies: {
        listByProfile: {
            reliesOnPath: 'profiles.list',
            properties: ['id'],
            url: 'https://management.azure.com/subscriptions/{id}/securityPolicies?api-version=2023-05-01'

        }
    },
    connectionPolicies: {
        listByServer: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/connectionPolicies?api-version=2021-05-01-preview'

        }
    },
    diskEncryptionSet: {
        get: {
            reliesOnPath: 'disks.list',
            properties: ['encryption.diskEncryptionSetId'],
            url: 'https://management.azure.com/{encryption.diskEncryptionSetId}?api-version=2023-04-02',
        }
    },
    encryptionScopes: {
        listByStorageAccounts: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/encryptionScopes?api-version=2023-01-01'
        }
    },
};

var tertiarycalls = {
    databaseBlobAuditingPolicies: {
        get: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/auditingSettings?api-version=2017-03-01-preview'
        }
    },
    diagnosticSettings: {
        listByEndpoint: {
            reliesOnPath: 'endpoints.listByProfile',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByBlobServices: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/blobServices/default/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByQueueServices: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/queueServices/default/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'

        },
        listByTableServices: {
            reliesOnPath: 'storageAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/tableServices/default/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'

        },
        listByAzureFrontDoor: {
            reliesOnPath: 'profiles.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByApplicationGateways: {
            reliesOnPath: 'applicationGateway.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByKeyVault: {
            reliesOnPath: 'vaults.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByLoadBalancer: {
            reliesOnPath: 'loadBalancers.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByDatabaseAccounts: {
            reliesOnPath: 'databaseAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByNetworkSecurityGroup: {
            reliesOnPath: 'networkSecurityGroups.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByRecoveryServiceVault: {
            reliesOnPath: 'recoveryServiceVaults.listBySubscriptionId',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByVirtualNetworks: {
            reliesOnPath: 'virtualNetworks.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByContainerRegistries: {
            reliesOnPath: 'registries.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByMediaService: {
            reliesOnPath: 'mediaServices.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByPostgresFlexibleServers: {
            reliesOnPath: 'servers.listPostgresFlexibleServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByPostgresServers: {
            reliesOnPath: 'servers.listPostgres',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByServiceBusNamespaces: {
            reliesOnPath: 'serviceBus.listNamespacesBySubscription',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByAksClusters: {
            reliesOnPath: 'managedClusters.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByAppConfigurations: {
            reliesOnPath: 'appConfigurations.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByRedisCache: {
            reliesOnPath: 'redisCaches.listBySubscription',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByAutomationAccounts: {
            reliesOnPath: 'automationAccounts.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByOpenAIAccounts: {
            reliesOnPath: 'openAI.listAccounts',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByDatabase: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByAppServices: {
            reliesOnPath: 'webApps.list',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByBastionHosts: {
            reliesOnPath: 'bastionHosts.listAll',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByDatabricksWorkspace: {
            reliesOnPath: 'databricks.listWorkspaces',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        },
        listByEventGridDomains: {
            reliesOnPath: 'eventGrid.listDomains',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview'
        }
    },
    backupShortTermRetentionPolicies: {
        listByDatabase: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/backupShortTermRetentionPolicies?api-version=2020-11-01-preview'
        }
    },
    getCertificatePolicy: {
        get: {
            reliesOnPath: 'vaults.getCertificates',
            properties: ['id'],
            url: '{id}/policy?api-version=7.3',
            vault: true
        }
    },
    syncGroups: {
        list: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/syncGroups?api-version=2021-11-01'
        }
    },
    ledgerDigestUploads: {
        list: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/ledgerDigestUploads?api-version=2021-11-01'
        }
    },
    transparentDataEncryption: {
        list: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/transparentDataEncryption?api-version=2021-11-01'
        }
    },
    dataMaskingPolicies: {
        get: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/dataMaskingPolicies/Default?api-version=2021-11-01',
        }
    },
    devOpsAuditingSettings: {
        list: {
            reliesOnPath: 'servers.listSql',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/devOpsAuditingSettings?api-version=2021-11-01'
        }
    },
    patchSchedules: {
        listByRedisCache: {
            reliesOnPath: 'redisCaches.listBySubscription',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/patchSchedules?api-version=2023-08-01'
        }
    },
    currentSensitivityLabels: {
        list: {
            reliesOnPath: 'databases.listByServer',
            properties: ['id'],
            url: 'https://management.azure.com/{id}/currentSensitivityLabels?api-version=2021-11-01'
        }
    },
};

var specialcalls = {
    tableService: {
        listTablesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        listTablesSegmentedNew: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        getProperties: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        sendIntegration: serviceMap['Table Service']
    },
    fileService: {
        listSharesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        sendIntegration: serviceMap['File Service']
    },
    blobService: {
        listContainersSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        getProperties: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        }
    },
    queueService: {
        listQueuesSegmented: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        listQueuesSegmentedNew: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        getProperties: {
            reliesOnPath: ['storageAccounts.listKeys'],
            rateLimit: 3000
        },
        sendIntegration: serviceMap['Queue Service']
    }
};

module.exports = {
    calls: calls,
    postcalls: postcalls,
    tertiarycalls: tertiarycalls,
    specialcalls: specialcalls,
    serviceMap: serviceMap
};
