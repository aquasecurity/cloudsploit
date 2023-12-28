var expect = require('chai').expect;
var redisCacheScheduledUpdates = require('./redisCacheScheduledUpdates');

const redisCaches = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisCacheScheduledUpdates': '1.2',
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Cache/Redis/test-cache',
        'location': 'East US',
        'name': 'test-cache',
        'type': 'Microsoft.Cache/Redis',
        'redisCacheScheduledUpdates': '1.1',
    }
];

const patchSchedules = {
  "id": "/subscriptions/123/resourceGroups/cloudsploit-dev/providers/Microsoft.Cache/Redis/omerredistest/patchSchedules/default",
      "location": "East US",
      "name": "omerredistest/default",
      "type": "Microsoft.Cache/Redis/PatchSchedules",
      "properties": {
        "scheduleEntries": [
          {
            "dayOfWeek": "Sunday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Monday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Tuesday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Wednesday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Thursday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Friday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          },
          {
            "dayOfWeek": "Saturday",
            "startHourUtc": 0,
            "maintenanceWindow": "PT5H"
          }
        ]
      }
};

const createCache = (redisCaches, patchSchedules) => {
    let redis = {};
    let patch = {};

    if (redisCaches) {
        redis['data'] = redisCaches;
        if (redisCaches && redisCaches.length) {
            patch[redisCaches[0].id] = {
                'data': patchSchedules
            };
        }
    }

    return {
        redisCaches: {
            listBySubscription: {
                'eastus': redis
            }
        },
        patchSchedules: {
            listByRedisCache: {
                'eastus': patch
            }
        }
    };
};

const createErrorCache = (redisCaches, message) => {
    let redis = {};
    let patch = {};

    if (redisCaches) {
        redis['data'] = redisCaches;
        if (redisCaches && redisCaches.length) {
            patch[redisCaches[0].id] = {
              'err': message
            };
        }
    }

    return {
        redisCaches: {
            listBySubscription: {
                'eastus': redis
            },
        },
        patchSchedules: {
            listByRedisCache: {
                'eastus': patch
            }
        }
    };
};

describe('redisCacheScheduledUpdates', function() {
    describe('run', function() {
        it('should give passing result if no redis caches', function(done) {
            const cache = createCache([]);
            redisCacheScheduledUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Redis Caches found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for redis caches', function(done) {
            const cache = createCache(null);
            redisCacheScheduledUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Caches');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query redis cache patch schedules', function(done) {
            const cache = createErrorCache([redisCaches[1]], 'notFound');
            redisCacheScheduledUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Redis Cache scheduled updates');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if redis cache does not have scheduled updates enabled', function(done) {
            const cache = createErrorCache([redisCaches[1]],'There are no patch schedules found for redis cache');
            redisCacheScheduledUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Redis Cache does not have scheduled updates enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if redis cache has scheduled updates enabled', function(done) {
            const cache = createCache([redisCaches[1]], patchSchedules);
            redisCacheScheduledUpdates.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Redis Cache has scheduled updates enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
