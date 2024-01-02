var expect = require('chai').expect;
var redisCacheDiagnosticLogs = require('./redisCacheDiagnosticLogs.js');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'minimumTlsVersion': '1.2',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'minimumTlsVersion': '1.1',
    },
];

const diagnosticSettings = [
    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/microsoft.cache/redis/omerredistest/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        workspaceId: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/test/providers/microsoft.operationalinsights/workspaces/ctolabsanalytics',
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        metrics: [ [Object] ],
        logs: [
            {
              category: null,
              categoryGroup: 'allLogs',
              enabled: true,
              retentionPolicy: { enabled: false, days: 0 }
            },
        ],
        logAnalyticsDestinationType: null
    },
    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/microsoft.cache/redis/omerredistest/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        workspaceId: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/test/providers/microsoft.operationalinsights/workspaces/ctolabsanalytics',
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        logs: [
            {
              category: 'ConnectedClientList',
              categoryGroup: null,
              enabled: false,
              retentionPolicy: { enabled: false, days: 0 }
            },
        ],
        logAnalyticsDestinationType: null
    },
    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/microsoft.cache/redis/omerredistest/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        workspaceId: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/test/providers/microsoft.operationalinsights/workspaces/ctolabsanalytics',
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        logs: [
            {
              category: 'ConnectedClientList',
              categoryGroup: null,
              enabled: true,
              retentionPolicy: { enabled: false, days: 0 }
            },
        ],
        logAnalyticsDestinationType: null
    },
    {},
    {
        id: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/cloudsploit-dev/providers/microsoft.cache/redis/omerredistest/providers/microsoft.insights/diagnosticSettings/test',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'test',
        location: null,
        kind: null,
        tags: null,
        identity: null,
        storageAccountId: null,
        serviceBusRuleId: null,
        workspaceId: '/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/test/providers/microsoft.operationalinsights/workspaces/ctolabsanalytics',
        eventHubAuthorizationRuleId: null,
        eventHubName: null,
        metrics: [ [Object] ],
        logs: [
        ],
        logAnalyticsDestinationType: null

    }
]

const createCache = (redisCaches, diagnostics) => {
    let diagnostic = {};
    if (redisCaches.length) {
        diagnostic[redisCaches[0].id] = {
            data: diagnostics
        };
    }


    return {
        redisCaches: {
            listBySubscription: {
                'eastus': {
                    data: redisCaches
                }
            }
        },
        diagnosticSettings: {
            listByRedisCache: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'redisCache') {
        return {
            redisCaches: {
                listBySubscription: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'nocache'){
        return {
            redisCaches: {
                listBySubscription: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            redisCaches: {
                listBySubscription: {
                    'eastus': {
                        data: [redisCaches[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByRedisCache: {
                    'eastus': {}
                }
            }
        };
    } else {
        const redisId = (redisCaches && redisCaches.length) ? redisCaches[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            redisCaches: {
                listBySubscription: {
                    'eastus': {
                        data: [redisCaches[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByRedisCache: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('redisCacheDiagnosticLogs', function () {
    describe('run', function () {

        it('should give pass result if No existing Redis Caches found', function (done) {
            const cache = createErrorCache('nocache');
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query Redis Caches:', function (done) {
            const cache = createErrorCache('redisCache');
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query diagnostics settings', function (done) {
            const cache = createErrorCache('settings');
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Cache diagnostics settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache has diagnostic logs enabled', function (done) {
            const cache = createCache([redisCaches[0]], [diagnosticSettings[2]]);
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache has diagnostic logs enabled with all Logs', function (done) {
            const cache = createCache([redisCaches[0]], [diagnosticSettings[0]]);
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Redis Cache does not have diagnostic logs enabled', function (done) {
            const cache = createCache([redisCaches[1]], [diagnosticSettings[1]]);
            redisCacheDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have diagnostic logs enabled for following:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Redis Cache does not have diagnostic logs enabled with settings', function (done) {
            const cache = createCache([redisCaches[1]], [diagnosticSettings[1]]);
            redisCacheDiagnosticLogs.run(cache, {diagnostic_logs: 'testsetting'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have diagnostic logs enabled for following:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Redis Cache has diagnostic logs enabled with * setting', function (done) {
            const cache = createCache([redisCaches[1]], [diagnosticSettings[1]]);
            redisCacheDiagnosticLogs.run(cache, {diagnostic_logs: '*'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Redis Cache has diagnostic logs enabled with * setting but there are not logs', function (done) {
            const cache = createCache([redisCaches[1]], [diagnosticSettings[4]]);
            redisCacheDiagnosticLogs.run(cache, {diagnostic_logs: '*'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});