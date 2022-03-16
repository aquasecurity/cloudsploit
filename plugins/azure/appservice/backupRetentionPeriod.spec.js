var expect = require('chai').expect;
var backupRetentionPeriod = require('./backupRetentionPeriod');

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

const backupConfigs = {
    id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Web/sites/akhtar-test',
    name: 'akhtar-test',
    type: 'Default',
    location: 'Central US',
    backupName: 'akhtar-test',
    enabled: true,
    storageAccountUrl: 'https://akhtarrgdiag.blob.core.windows.net/appbackup?sp=rwdl&st=2022-03-16T07:51:37Z&se=2295-12-29T08:51:37Z&sv=2020-08-04&sr=c&sig=FeC0hGUrqJb6b%2Bh5qbIif84725sMjeqyNUzWa4tL3L4%3D',
    backupSchedule: {
      frequencyInterval: 7,
      frequencyUnit: 'Day',
      keepAtLeastOneBackup: true,
      retentionPeriodInDays: 7,
      startTime: '2022-03-16T07:51:38.699',
      lastExecutionTime: '2022-03-16T07:53:38.4131659'
    },
    databases: [],
    mySqlDumpParams: null
};

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
            getBackupConfiguration: {
                'eastus': config
            }
        }
    };
};

describe('backupRetentionPeriod', function() {
    describe('run', function() {
        it('should give passing result if no web apps', function(done) {
            const cache = createCache([]);
            backupRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Web Apps found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web apps', function(done) {
            const cache = createCache();
            backupRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web Apps');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if web apps backups can not be configured', function(done) {
            const cache = createCache([webApps[1]], []);
            backupRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WebApps backup can not be configured for the function App');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give failing result if no web app backup config found', function(done) {
            const cache = createCache([webApps[0]], []);
            backupRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No backup configurations found for this WebApp');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for web app backup configs', function(done) {
            const cache = createCache([webApps[0]]);
            backupRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Web App Backup Configs');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if web app backup retention period is within the recommended threshold', function(done) {
            const cache = createCache([webApps[0]], backupConfigs);
            backupRetentionPeriod.run(cache, { webapps_backup_retention_period: 7 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WebApp has a backup retention period of 7 of 7 days');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if web app backup retention period is below the recommended threshold', function(done) {
            const cache = createCache([webApps[0]], backupConfigs);
            backupRetentionPeriod.run(cache, { webapps_backup_retention_period: 10 }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WebApp has a backup retention period of 7 of 10 days limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
