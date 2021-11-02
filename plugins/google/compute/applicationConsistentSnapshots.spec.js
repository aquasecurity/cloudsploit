var expect = require('chai').expect;
var plugin = require('./applicationConsistentSnapshots');


const schedules = [
      {
        "id": "11111",
        "creationTimestamp": "2021-10-09T10:17:01.727-07:00",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/resourcePolicies/schedule-1",
        "region": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1",
        "name": "schedule-1",
        "snapshotSchedulePolicy": {
          "schedule": {
            "weeklySchedule": {
              "dayOfWeeks": [
                {
                  "day": "TUESDAY",
                  "startTime": "03:00",
                  "duration": "PT14400S"
                }
              ]
            }
          },
          "retentionPolicy": {
            "maxRetentionDays": 14,
            "onSourceDiskDelete": "KEEP_AUTO_SNAPSHOTS"
          },
          "snapshotProperties": {
            "storageLocations": [
              "us-central1"
            ],
            "guestFlush": true
          }
        },
        "status": "READY",
        "kind": "compute#resourcePolicy"
      },
      {
        "id": "111111",
        "creationTimestamp": "2021-10-09T10:20:00.717-07:00",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/resourcePolicies/schedule-2",
        "region": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1",
        "name": "schedule-2",
        "snapshotSchedulePolicy": {
          "schedule": {
            "dailySchedule": {
              "daysInCycle": 1,
              "startTime": "03:00",
              "duration": "PT14400S"
            }
          },
          "retentionPolicy": {
            "maxRetentionDays": 14,
            "onSourceDiskDelete": "KEEP_AUTO_SNAPSHOTS"
          },
          "snapshotProperties": {
            "storageLocations": [
              "us-central1"
            ],
            "guestFlush": false
          }
        },
        "status": "READY",
        "kind": "compute#resourcePolicy"
    
    }
];

const createCache = (list, err) => {
  
    return {
        resourcePolicies: {
            list: {
                'us-central1': {
                    err: err,
                    data: list
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [{ name: 'test-project' }]
                }
            }
        }
    }
};

describe('applicationConsistentSnapshots', function () {
    describe('run', function () {

        it('should give unknown if unable to query schedules', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for snapshot schedules');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });


        it('should give passing result if no snapshot schedules found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No snapshot schedules found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if snapshot schedule is configured to take application-consistent snapshots', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is configured to take application-consistent snapshots');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [schedules[0]],
                null
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if snapshot schedule is not configured to take application-consistent snapshots', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not configured to take application-consistent snapshots');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [schedules[1]],
                null            );

            plugin.run(cache, {}, callback);
        });

    })
});

