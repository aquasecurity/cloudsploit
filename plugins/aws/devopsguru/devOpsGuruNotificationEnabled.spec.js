var expect = require('chai').expect;
const devOpsGuruNotificationEnabled = require('./devOpsGuruNotificationEnabled');

const listNotificationChannels = [
    {
        "Id": "fe73f5d8-e8ca-45d1-98e9-e2c0f6cc6d9f",
        "Config": {
            "Sns": {
                "TopicArn": "arn:aws:sns:us-east-1:000011112222:devopsguru"
            }
        }
    }
];

const createCache = (data, err) => {
    return {
        devopsguru: {
            listNotificationChannels: {
                'us-east-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

const createNullCache = () => {
    return {
        devopsguru: {
            listNotificationChannels: {
                'us-east-1': null
            }
        }
    }
};

describe('devOpsGuruNotificationEnabled', function () {
    describe('run', function () {
        it('should PASS if SNS notification is configured for DevOps Guru', function (done) {
            const cache = createCache(listNotificationChannels);
            devOpsGuruNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if SNS notification is configured for DevOps Guru', function (done) {
            const cache = createCache([]);
            devOpsGuruNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list notification channels', function (done) {
            const cache = createCache(listNotificationChannels, { message: 'unable to list notification channels' });
            devOpsGuruNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list notification channels response not found', function (done) {
            const cache = createNullCache();
            devOpsGuruNotificationEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
