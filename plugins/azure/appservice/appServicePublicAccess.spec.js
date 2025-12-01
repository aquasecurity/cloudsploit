var expect = require('chai').expect;
var appServicePublicAccess = require('./appServicePublicAccess');

const webApps = [
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-1',
        'name': 'test-app-1',
        'type': 'Microsoft.Web/sites',
        'kind': 'app',
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-2',
        'name': 'test-app-2',
        'type': 'Microsoft.Web/sites',
        'kind': 'app',
        'location': 'eastus'
    },
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-3',
        'name': 'test-app-3',
        'type': 'Microsoft.Web/sites',
        'kind': 'functionapp',
        'location': 'eastus'
    }
];

const listConfigurations = [
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-1/config/web',
        'name': 'web',
        'publicNetworkAccess': 'Disabled'
    },
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-2/config/web',
        'name': 'web',
        'publicNetworkAccess': 'Enabled'
    },
    {
        'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-3/config/web',
        'name': 'web'
    }
];

const createCache = (webApps, configurations, webAppsErr, configurationsErr) => {
    const appId = (webApps && webApps.length) ? webApps[0].id : null;
    return {
        webApps: {
            list: {
                'eastus': {
                    err: webAppsErr,
                    data: webApps
                }
            },
            listConfigurations: {
                'eastus': {
                    [appId]: {
                        err: configurationsErr,
                        data: configurations
                    }
                }
            }
        }
    };
};

describe('appServicePublicAccess', function () {
    describe('run', function () {
        it('should give passing result if no web apps found', function (done) {
            const cache = createCache([], null);
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Services found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function (done) {
            const cache = createCache(null, null, { message: 'Unable to query Web Apps' });
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for App Services');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query web app configuration', function (done) {
            const cache = createCache([webApps[0]], null, null, { message: 'Unable to query configuration' });
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Service configuration');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if App Service has public network access disabled', function (done) {
            const cache = createCache([webApps[0]], [listConfigurations[0]]);
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Service has public network access enabled', function (done) {
            const cache = createCache([webApps[1]], [listConfigurations[1]]);
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Service publicNetworkAccess property is not set', function (done) {
            const cache = createCache([webApps[2]], [listConfigurations[2]]);
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Service does not have public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result for App Service with case-insensitive disabled value', function (done) {
            const config = [{
                'id': '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Web/sites/test-app-1/config/web',
                'name': 'web',
                'publicNetworkAccess': 'disabled'
            }];
            const cache = createCache([webApps[0]], config);
            appServicePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Service has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});