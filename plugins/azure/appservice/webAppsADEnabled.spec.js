var expect = require('chai').expect;
var webAppsADEnabled = require('./webAppsADEnabled');

const webApps = [
    {
        id: '/subscriptions/abcdefg-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/test/providers/Microsoft.Web/sites/test',
        name: 'test',
        type: 'Microsoft.Web/sites',
        kind: 'app,linux',
        location: 'Central US',
        state: 'Running',
        hostNames: [ 'test.azurewebsites.net' ],
        webSpace: 'test-CentralUSwebspace-Linux',
        selfLink: 'https://waws-prod-dm1-213.api.azurewebsites.windows.net:454/subscriptions/abcdefg-ebf6-437f-a3b0-28fc0d22117e/webspaces/test-CentralUSwebspace-Linux/sites/test',
        repositorySiteName: 'test',
        owner: null,
        usageState: 'Normal',
        enabled: true,
        adminEnabled: true,
        enabledHostNames: [
          'test.azurewebsites.net',
          'test.scm.azurewebsites.net'
        ]
    },
    {
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Web/sites/test-app',
        name: 'test-app',
        type: 'Microsoft.Web/sites',
        kind: 'functionapp',
        location: 'East US',
        identity: {
            type: 'SystemAssigned',
            tenantId: '2d4f0836-5935-47f5-954c-14e713119ac2',
            principalId: '66cddca0-05fa-4ef7-a219-b145f7d9dc6d'
          },
    }
];

const createCache = (apps) => {
    return {
        webApps: {
            list: {
                'eastus': {
                    data: apps
                }
            }
        }
    };
};

describe('webAppsADEnabled', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            webAppsADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache(null);
            webAppsADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Registration with Azure Entra ID is enabled', function(done) {
            const cache = createCache([webApps[1]]);
            webAppsADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Registration with Azure Entra ID is enabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Registration with Azure Entra ID is disabled', function(done) {
            const cache = createCache([webApps[0]]);
            webAppsADEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Registration with Azure Entra ID is disabled for the Web App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
