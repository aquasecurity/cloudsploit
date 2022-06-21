var expect = require('chai').expect;
var appInsightsEnabled = require('./appInsightsEnabled');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'app,linux',
        'location': 'East US'
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        'name': 'test-app',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'East US'
    }
];

const appSettings = [
    {
        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Web/sites/akhtar-test/config/appsettings',
        name: 'appsettings',
        type: 'Microsoft.Web/sites/config',
        location: 'Central US',
        APPINSIGHTS_INSTRUMENTATIONKEY: '2f521d9c-2a65-4ab2-8108-8b8a0902790e',
        APPLICATIONINSIGHTS_CONNECTION_STRING: 'InstrumentationKey=2f521d9c-2a65-4ab2-8108-8b8a0902790e;IngestionEndpoint=https://centralus-2.in.applicationinsights.azure.com/',
        ApplicationInsightsAgent_EXTENSION_VERSION: '~3',
        XDT_MicrosoftApplicationInsights_Mode: 'default',
        APPINSIGHTS_PROFILERFEATURE_VERSION: 'disabled',
        DiagnosticServices_EXTENSION_VERSION: 'disabled',
        APPINSIGHTS_SNAPSHOTFEATURE_VERSION: 'disabled',
        SnapshotDebugger_EXTENSION_VERSION: 'disabled',
        InstrumentationEngine_EXTENSION_VERSION: 'disabled',
        XDT_MicrosoftApplicationInsights_BaseExtensions: 'disabled',
        XDT_MicrosoftApplicationInsights_PreemptSdk: 'disabled'
    },
    {
        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Web/sites/akhtar-test/config/appsettings',
        name: 'appsettings',
        type: 'Microsoft.Web/sites/config',
        location: 'Central US',
        APPINSIGHTS_INSTRUMENTATIONKEY: '2f521d9c-2a65-4ab2-8108-8b8a0902790e',
        APPLICATIONINSIGHTS_CONNECTION_STRING: 'InstrumentationKey=2f521d9c-2a65-4ab2-8108-8b8a0902790e;IngestionEndpoint=https://centralus-2.in.applicationinsights.azure.com/',
        ApplicationInsightsAgent_EXTENSION_VERSION: 'default',
        XDT_MicrosoftApplicationInsights_Mode: 'default',
        APPINSIGHTS_PROFILERFEATURE_VERSION: 'disabled',
        DiagnosticServices_EXTENSION_VERSION: 'disabled',
        APPINSIGHTS_SNAPSHOTFEATURE_VERSION: 'disabled',
        SnapshotDebugger_EXTENSION_VERSION: 'disabled',
        InstrumentationEngine_EXTENSION_VERSION: 'disabled',
        XDT_MicrosoftApplicationInsights_BaseExtensions: 'disabled',
        XDT_MicrosoftApplicationInsights_PreemptSdk: 'disabled'
    }
];

const createCache = (webApps, configs) => {
    let app = {};
    let config = {};

    if (webApps) {
        app['data'] = webApps;
        if (webApps && webApps.length) {
            config[webApps[0].id] = {
                'data': configs
            };
        }
    }

    return {
        webApps: {
            list: {
                'eastus': app
            },
            listAppSettings: {
                'eastus': config
            }
        }
    };
};

describe('appInsightsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if application insights can not be configured', function(done) {
            const cache = createCache([webApps[1]], []);
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application insights feature cannot be configured for the function App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web app settings', function(done) {
            const cache = createCache([webApps[0]]);
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Insights:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if application insights is enabled', function(done) {
            const cache = createCache([webApps[0]], appSettings[0]);
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Insights feature is enabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if always on is disabled', function(done) {
            const cache = createCache([webApps[0]], appSettings[1]);
            appInsightsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Insights feature is disabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 