var expect = require('chai').expect;
var nsgFlowLogsRetentionPeriod = require('./nsgFlowLogsRetentionPeriod');

const networkWatchers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus',
        'name': 'NetworkWatcher_eastus'
    }
];

const flowLogs = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus/flowLogs/test-flowlog',
        'name': 'test-flowlog',
        'retentionPolicy': {
            'days': 100,
            'enabled': true
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus/flowLogs/test-flowlog',
        'name': 'test-flowlog',
        'retentionPolicy': {
            'days': 45,
            'enabled': true
        }
    }
];


const createCache = (Watchers, flowLogs) => {
    let logs = {};
    if (Watchers.length > 0) {
        logs[Watchers[0].id] = {
            data: flowLogs
        };
    }

    return {
        networkWatchers: {
            listAll: {
                'eastus': {
                    data: Watchers
                }
            }
        },
        flowLogs: {
            list: {
                'eastus': logs
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key === 'watcher') {
        return {
            networkWatchers: {
                listAll: {
                    'eastus': {}
                }
            }
        };
    } else {
        return {
            networkWatchers: {
                listAll: {
                    'eastus': {
                        data: [networkWatchers[0]]
                    }
                }
            },
            flowLogs: {
                list: {
                    'eastus': {}
                }
            }
        };
    }
};

describe('nsgFlowLogsRetentionPeriod', function() {
    describe('run', function() {
        it('should give passing result if no network watchers', function(done) {
            const cache = createCache([], []);
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Network Watchers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no flow logs', function(done) {
            const cache = createCache([networkWatchers[0]],[]);
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No flow logs data found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for network watchers', function(done) {
            const cache = createErrorCache('watcher');
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Watchers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for flow logs', function(done) {
            const cache = createErrorCache('flowLog');
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for flow logs data:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if flow logs have desired retention period set', function(done) {
            const cache = createCache([networkWatchers[0]], [flowLogs[0]]);
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('NSG fLow log has retention period set to 100 of 90 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if flow logs do not have desired retention period set', function(done) {
            const cache = createCache([networkWatchers[0]], [flowLogs[1]]);
            nsgFlowLogsRetentionPeriod.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('NSG fLow log has retention period set to 45 of 90 days desired limit');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});